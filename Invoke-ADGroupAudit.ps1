#Requires -Module ActiveDirectory

<#
   Copyright 2025 David Hodson

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
#>

<#
.SYNOPSIS
    Audits Active Directory and Azure AD groups for security and compliance issues
    
.DESCRIPTION
    Performs comprehensive analysis of AD groups (on-premises and Azure AD) to identify 
    empty groups, disabled accounts, naming compliance violations, and nested group structures. 
    Generates detailed reports suitable for security audits and compliance requirements.
    
    Features include:
    - Empty group detection (on-premises and Azure AD)
    - Disabled user/computer account identification
    - Group naming standards validation
    - Nested group analysis with member counts
    - High-performance caching for large environments
    - Professional HTML and CSV reporting
    - Support for both on-premises AD and Azure AD
    
.PARAMETER SearchBase
    Distinguished name of the organizational unit to limit the audit scope.
    Only applies to on-premises Active Directory. If not specified, audits all groups in the domain.
    
.PARAMETER ExportPath
    Full path for CSV export file. Creates detailed spreadsheet with all findings.
    
.PARAMETER ExportHTML
    Full path for HTML report file. Generates executive-ready dashboard report.
    
.PARAMETER ShowProgress
    Displays real-time progress information including cache statistics and processing rates.
    
.PARAMETER AzureADOnly
    Audit only Azure AD groups. Requires Microsoft.Graph or AzureAD PowerShell module.
    
.PARAMETER OnPremisesOnly
    Audit only on-premises Active Directory groups. Default behavior if no Azure switches used.
    
.PARAMETER IncludeBoth
    Audit both on-premises and Azure AD groups in a single report.
    
.PARAMETER TenantId
    Azure AD Tenant ID (GUID). Required for Azure AD operations if not already connected.
    
.EXAMPLE
    .\Invoke-ADGroupAudit.ps1
    
    Performs basic on-premises domain-wide audit with console output only.
    
.EXAMPLE
    .\Invoke-ADGroupAudit.ps1 -AzureADOnly -ShowProgress -ExportHTML "C:\Reports\azure-audit.html"
    
    Audits only Azure AD groups with progress display and generates HTML report.
    
.EXAMPLE
    .\Invoke-ADGroupAudit.ps1 -IncludeBoth -ExportPath "complete-audit.csv" -ShowProgress
    
    Audits both on-premises and Azure AD groups, exports to CSV with progress monitoring.
    
.EXAMPLE
    .\Invoke-ADGroupAudit.ps1 -SearchBase "OU=Finance,DC=contoso,DC=com" -OnPremisesOnly
    
    Audits only Finance OU groups in on-premises AD.
    
.INPUTS
    None. Does not accept pipeline input.
    
.OUTPUTS
    System.Object[]
    Returns array of group analysis objects when run interactively.
    
.NOTES
    Author: David Hodson
    Version: 2.0
    Requires: PowerShell 5.1+, ActiveDirectory Module for on-premises
              Microsoft.Graph or AzureAD module for Azure AD
    
    For Azure AD: Requires appropriate permissions (Group.Read.All minimum)
    Performance: Processes 5-15 groups/second depending on environment size.
#>

param(
    [string]$SearchBase,
    [string]$ExportPath,
    [string]$ExportHTML,
    [switch]$ShowProgress,
    [switch]$AzureADOnly,
    [switch]$OnPremisesOnly,
    [switch]$IncludeBoth,
    [string]$TenantId
)

# Initialize caches at script level
$script:UserStatusCache = @{}
$script:ComputerStatusCache = @{}
$script:NestedGroupCache = @{}
$script:AzureUserCache = @{}
$script:AzureGroupCache = @{}

# Module availability tracking
$script:HasOnPremAD = $false
$script:HasAzureAD = $false
$script:AzureModule = $null

# Simple banner
function Show-Banner {
    Write-Host "AD Group Audit Tool" -ForegroundColor Cyan
    Write-Host "Finding empty groups, disabled members, nested groups, and name issues..." -ForegroundColor White
    Write-Host ""
}

# Function to check and import required modules
function Test-RequiredModules {
    param($IncludeAzure, $OnPremisesOnly)
    
    # Check on-premises AD module
    if (-not $OnPremisesOnly -or $IncludeAzure -or (-not $AzureADOnly)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $script:HasOnPremAD = $true
            Write-Host "✅ Active Directory module loaded" -ForegroundColor Green
        }
        catch {
            if (-not $AzureADOnly) {
                Write-Host "❌ Active Directory module not available: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "   Install RSAT-AD-PowerShell feature or run from domain controller" -ForegroundColor Yellow
            }
        }
    }
    
    # Check Azure AD modules
    if ($IncludeAzure -or $AzureADOnly) {
        # Try Microsoft.Graph first (preferred)
        try {
            Import-Module Microsoft.Graph.Groups -ErrorAction Stop
            Import-Module Microsoft.Graph.Users -ErrorAction Stop
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            $script:HasAzureAD = $true
            $script:AzureModule = "Graph"
            Write-Host "✅ Microsoft Graph modules loaded" -ForegroundColor Green
        }
        catch {
            # Fallback to AzureAD module
            try {
                Import-Module AzureAD -ErrorAction Stop
                $script:HasAzureAD = $true
                $script:AzureModule = "AzureAD"
                Write-Host "✅ AzureAD module loaded" -ForegroundColor Green
                Write-Host "   Consider upgrading to Microsoft.Graph modules for better performance" -ForegroundColor Yellow
            }
            catch {
                Write-Host "❌ No Azure AD modules available" -ForegroundColor Red
                Write-Host "   Install Microsoft.Graph or AzureAD PowerShell module" -ForegroundColor Yellow
                Write-Host "   Install-Module Microsoft.Graph (recommended)" -ForegroundColor Yellow
                Write-Host "   Install-Module AzureAD (legacy)" -ForegroundColor Yellow
                return $false
            }
        }
    }
    
    return $true
}

# Function to connect to Azure AD
function Connect-ToAzureAD {
    param($TenantId)
    
    if (-not $script:HasAzureAD) {
        return $false
    }
    
    try {
        if ($script:AzureModule -eq "Graph") {
            # Check if already connected
            try {
                $context = Get-MgContext -ErrorAction Stop
                if ($context -and $context.TenantId) {
                    Write-Host "✅ Already connected to Microsoft Graph (Tenant: $($context.TenantId))" -ForegroundColor Green
                    return $true
                }
            }
            catch {
                # Not connected, continue with connection
            }
            
            # Connect to Microsoft Graph
            $connectParams = @{
                Scopes = @('Group.Read.All', 'User.Read.All', 'GroupMember.Read.All')
                NoWelcome = $true
            }
            if ($TenantId) {
                $connectParams.TenantId = $TenantId
            }
            
            Connect-MgGraph @connectParams -ErrorAction Stop
            Write-Host "✅ Connected to Microsoft Graph" -ForegroundColor Green
        }
        else {
            # AzureAD module
            $connectParams = @{}
            if ($TenantId) {
                $connectParams.TenantId = $TenantId
            }
            
            Connect-AzureAD @connectParams -ErrorAction Stop | Out-Null
            Write-Host "✅ Connected to Azure AD" -ForegroundColor Green
        }
        return $true
    }
    catch {
        Write-Host "❌ Failed to connect to Azure AD: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to check for problematic characters in group names
function Test-GroupNameCompliance {
    param($GroupName)
    
    $issues = @()
    $recommendations = @()
    
    # Check for spaces
    if ($GroupName -match '\s') {
        $issues += "Contains spaces"
        $recommendations += "Consider using underscores or hyphens instead of spaces"
    }
    
    # Check for special characters that can cause issues
    $specialChars = @('\/', '\\', '\[', '\]', ':', ';', '\|', '=', ',', '\+', '\*', '\?', '<', '>', '"', '@', '#', '\$', '%', '&', '\(', '\)')
    $foundSpecialChars = @()
    
    foreach ($char in $specialChars) {
        if ($GroupName -match $char) {
            $foundSpecialChars += $char -replace '\\', ''
        }
    }
    
    if ($foundSpecialChars.Count -gt 0) {
        $issues += "Contains special characters: $($foundSpecialChars -join ', ')"
        $recommendations += "Remove or replace special characters with hyphens or underscores"
    }
    
    # Check for leading/trailing spaces or dots
    if ($GroupName -match '^\s' -or $GroupName -match '\s$') {
        $issues += "Has leading or trailing spaces"
        $recommendations += "Remove leading and trailing spaces"
    }
    
    if ($GroupName -match '^\.' -or $GroupName -match '\.$') {
        $issues += "Starts or ends with a period"
        $recommendations += "Remove leading and trailing periods"
    }
    
    # Check for very long names
    if ($GroupName.Length -gt 64) {
        $issues += "Name exceeds 64 characters ($($GroupName.Length) chars)"
        $recommendations += "Consider shortening the group name for better compatibility"
    }
    
    # Check for very short names
    if ($GroupName.Length -lt 3) {
        $issues += "Name is very short ($($GroupName.Length) chars)"
        $recommendations += "Consider using a more descriptive name"
    }
    
    # Check for numeric-only names
    if ($GroupName -match '^\d+$') {
        $issues += "Name contains only numbers"
        $recommendations += "Add descriptive text to the group name"
    }
    
    return @{
        HasIssues = $issues.Count -gt 0
        Issues = $issues -join "; "
        Recommendations = $recommendations -join "; "
    }
}

# Azure AD specific functions
function Get-AzureADGroupMembers {
    param($GroupId)
    
    try {
        if ($script:AzureModule -eq "Graph") {
            $members = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop
            return @{
                Success = $true
                Members = $members
                Method = "Graph"
            }
        }
        else {
            $members = Get-AzureADGroupMember -ObjectId $GroupId -All $true -ErrorAction Stop
            return @{
                Success = $true
                Members = $members
                Method = "AzureAD"
            }
        }
    }
    catch {
        return @{
            Success = $false
            Reason = $_.Exception.Message
        }
    }
}

function Test-AzureADUserEnabled {
    param($UserId, $UserObject = $null)
    
    # Check cache first
    if ($script:AzureUserCache.ContainsKey($UserId)) {
        return $script:AzureUserCache[$UserId]
    }
    
    try {
        # Always fetch fresh user object with explicit properties
        if ($script:AzureModule -eq "Graph") {
            $user = Get-MgUser -UserId $UserId -Property "AccountEnabled,DisplayName,UserType" -ErrorAction Stop
            $enabled = $user.AccountEnabled
            $name = $user.DisplayName
            $userType = $user.UserType
        } else {
            $user = Get-AzureADUser -ObjectId $UserId -ErrorAction Stop
            $enabled = $user.AccountEnabled
            $name = $user.DisplayName
            $userType = $user.UserType
        }
        
        # Handle guest users and different user types
        if ($userType -eq "Guest") {
            # Guest users might have different enabled logic
            # For now, treat guests same as regular users
        }
        
        # Handle various data type possibilities
        if ($null -eq $enabled) {
            $finalEnabled = $null
        } elseif ($enabled -is [string]) {
            $finalEnabled = $enabled -eq "True" -or $enabled -eq "true" -or $enabled -eq "1"
        } elseif ($enabled -is [int]) {
            $finalEnabled = $enabled -eq 1
        } else {
            # Handle boolean responses (most common)
            $finalEnabled = [bool]$enabled
        }
        
        $result = @{
            Enabled = $finalEnabled
            Name = $name
            Type = "User"
            Source = "AzureAD"
            UserType = $userType
        }
        
        $script:AzureUserCache[$UserId] = $result
        return $result
    }
    catch {
        # Log the specific error for debugging
        Write-Verbose "Error checking Azure AD user $UserId : $($_.Exception.Message)"
        
        $result = @{
            Enabled = $null
            Name = "Unknown"
            Type = "User"
            Source = "AzureAD"
            UserType = "Unknown"
        }
        $script:AzureUserCache[$UserId] = $result
        return $result
    }
}
function Get-AzureADNestedGroups {
    param($GroupId)
    
    # Check cache first
    if ($script:NestedGroupCache.ContainsKey($GroupId)) {
        return $script:NestedGroupCache[$GroupId]
    }
    
    $nestedGroups = @()
    
    try {
        $memberResult = Get-AzureADGroupMembers -GroupId $GroupId
        if ($memberResult.Success) {
            foreach ($member in $memberResult.Members) {
                $memberType = if ($script:AzureModule -eq "Graph") { 
                    $member.AdditionalProperties.'@odata.type' 
                } else { 
                    $member.ObjectType 
                }
                
                if ($memberType -like "*group*" -or $memberType -eq "Group") {
                    try {
                        # Get member count for nested group
                        $nestedMemberResult = Get-AzureADGroupMembers -GroupId $member.Id
                        $memberCount = if ($nestedMemberResult.Success) { $nestedMemberResult.Members.Count } else { "Unknown" }
                        
                        $displayName = if ($script:AzureModule -eq "Graph") { $member.AdditionalProperties.displayName } else { $member.DisplayName }
                        
                        $nestedGroups += [PSCustomObject]@{
                            Name = $displayName
                            Id = $member.Id
                            Level = 1
                            MemberCount = $memberCount
                        }
                    }
                    catch {
                        continue
                    }
                }
            }
        }
        
        $script:NestedGroupCache[$GroupId] = $nestedGroups
    }
    catch {
        $script:NestedGroupCache[$GroupId] = @()
    }
    
    return $nestedGroups
}

function Test-AzureADGroupHealth {
    param($Group)
    
    $memberResult = Get-AzureADGroupMembers -GroupId $Group.Id
    
    if (-not $memberResult.Success) {
        return $null
    }
    
    # Check group name compliance
    $groupName = if ($script:AzureModule -eq "Graph") { $Group.DisplayName } else { $Group.DisplayName }
    $nameCompliance = Test-GroupNameCompliance -GroupName $groupName
    
    $members = $memberResult.Members
    $totalMembers = $members.Count
    
    # Get nested groups
    $nestedGroups = Get-AzureADNestedGroups -GroupId $Group.Id
    
    # Analyze members by type
    $userMembers = @()
    $groupMembers = @()
    $otherMembers = 0
    
    foreach ($member in $members) {
        $memberType = if ($script:AzureModule -eq "Graph") { 
            $member.AdditionalProperties.'@odata.type' 
        } else { 
            $member.ObjectType 
        }
        
        if ($memberType -like "*user*" -or $memberType -eq "User") {
            $userMembers += $member
        }
        elseif ($memberType -like "*group*" -or $memberType -eq "Group") {
            $groupMembers += $member
        }
        else {
            $otherMembers++
        }
    }
    
    # Prepare nested group information
    $nestedGroupNames = ($nestedGroups | ForEach-Object { "$($_.Name) ($($_.MemberCount) members)" }) -join "; "
    
    # Quick exit for empty groups
    if ($totalMembers -eq 0) {
        return [PSCustomObject]@{
            GroupName = $groupName
            GroupType = "AzureAD"
            GroupScope = "Unknown"
            TotalMembers = 0
            UserMembers = 0
            ComputerMembers = 0
            EnabledUsers = 0
            DisabledUsers = 0
            DisabledUserNames = ""
            EnabledComputers = 0
            DisabledComputers = 0
            DisabledComputerNames = ""
            OtherMembers = 0
            NestedGroupCount = 0
            NestedGroupNames = ""
            NameCompliant = -not $nameCompliance.HasIssues
            NameIssues = $nameCompliance.Issues
            Status = if ($nameCompliance.HasIssues) { "Empty + Name Issues" } else { "Empty" }
            Issue = if ($nameCompliance.HasIssues) { "Group has no members; $($nameCompliance.Issues)" } else { "Group has no members" }
            Recommendation = if ($nameCompliance.HasIssues) { "Consider removing this group; $($nameCompliance.Recommendations)" } else { "Consider removing this group" }
            DistinguishedName = $Group.Id
            Source = "AzureAD"
        }
    }
    # Quick exit if no user members
    if ($userMembers.Count -eq 0) {
        return [PSCustomObject]@{
            GroupName = $groupName
            GroupType = "AzureAD"
            GroupScope = "Unknown"
            TotalMembers = $totalMembers
            UserMembers = 0
            ComputerMembers = 0
            EnabledUsers = 0
            DisabledUsers = 0
            DisabledUserNames = ""
            EnabledComputers = 0
            DisabledComputers = 0
            DisabledComputerNames = ""
            OtherMembers = $otherMembers
            NestedGroupCount = $nestedGroups.Count
            NestedGroupNames = $nestedGroupNames
            NameCompliant = -not $nameCompliance.HasIssues
            NameIssues = $nameCompliance.Issues
            Status = if ($nameCompliance.HasIssues) { "No Users + Name Issues" } else { "No Users" }
            Issue = if ($nameCompliance.HasIssues) { "Group contains no user accounts; $($nameCompliance.Issues)" } else { "Group contains no user accounts" }
            Recommendation = if ($nameCompliance.HasIssues) { "Review group membership; $($nameCompliance.Recommendations)" } else { "Review group membership" }
            DistinguishedName = $Group.Id
            Source = "AzureAD"
        }
    }
    
    # Check user status
    $enabledUsers = 0
    $disabledUsers = 0
    $unknownUsers = 0
    $disabledUserNames = @()
    
    foreach ($user in $userMembers) {
        $userInfo = Test-AzureADUserEnabled -UserId $user.Id -UserObject $user
        switch ($userInfo.Enabled) {
            $true { $enabledUsers++ }
            $false { 
                $disabledUsers++
                $disabledUserNames += $userInfo.Name
            }
            $null { $unknownUsers++ }
        }
    }
    
    # Determine status
    $status = "Healthy"
    $issue = ""
    $recommendation = ""
    
    if ($enabledUsers -eq 0 -and ($disabledUsers -gt 0 -or $unknownUsers -gt 0)) {
        $status = "Only Disabled"
        $issue = "Group contains only disabled accounts"
        $recommendation = "Remove disabled accounts or delete group"
    } elseif ($disabledUsers -gt 0) {
        $status = "Has Disabled"
        $issue = "$disabledUsers disabled user(s) in group"
        $recommendation = "Remove disabled accounts"
    } elseif ($unknownUsers -gt 0) {
        $status = "Has Unknown"
        $issue = "$unknownUsers user(s) could not be verified"
        $recommendation = "Investigate unresolvable accounts"
    }
    
    # Add name compliance issues
    if ($nameCompliance.HasIssues) {
        if ($status -eq "Healthy") {
            $status = "Name Issues"
            $issue = $nameCompliance.Issues
            $recommendation = $nameCompliance.Recommendations
        } else {
            $status += " + Name Issues"
            $issue += "; " + $nameCompliance.Issues
            $recommendation += "; " + $nameCompliance.Recommendations
        }
    }
    
    return [PSCustomObject]@{
        GroupName = $groupName
        GroupType = "AzureAD"
        GroupScope = "Unknown"
        TotalMembers = $totalMembers
        UserMembers = $userMembers.Count
        ComputerMembers = 0  # Azure AD doesn't have computer objects like on-premises
        EnabledUsers = $enabledUsers
        DisabledUsers = $disabledUsers
        DisabledUserNames = ($disabledUserNames -join "; ")
        EnabledComputers = 0
        DisabledComputers = 0
        DisabledComputerNames = ""
        OtherMembers = $otherMembers
        NestedGroupCount = $nestedGroups.Count
        NestedGroupNames = $nestedGroupNames
        NameCompliant = -not $nameCompliance.HasIssues
        NameIssues = $nameCompliance.Issues
        Status = $status
        Issue = $issue
        Recommendation = $recommendation
        DistinguishedName = $Group.Id
        Source = "AzureAD"
    }
}

# Original on-premises functions (keeping existing code)
function Get-NestedGroups {
    param($GroupDN)
    
    if ($script:NestedGroupCache.ContainsKey($GroupDN)) {
        return $script:NestedGroupCache[$GroupDN]
    }
    
    $nestedGroups = @()
    
    try {
        $group = Get-ADGroup -Identity $GroupDN -Properties member -ErrorAction Stop
        
        if ($group.member) {
            foreach ($memberDN in $group.member) {
                try {
                    $member = Get-ADObject -Identity $memberDN -Properties objectClass -ErrorAction Stop
                    if ($member.objectClass -eq 'group') {
                        $memberCount = 0
                        try {
                            $nestedGroup = Get-ADGroup -Identity $memberDN -Properties member -ErrorAction Stop
                            $memberCount = if ($nestedGroup.member) { $nestedGroup.member.Count } else { 0 }
                        }
                        catch {
                            $memberCount = "Unknown"
                        }
                        
                        $nestedGroups += [PSCustomObject]@{
                            Name = $member.Name
                            DistinguishedName = $memberDN
                            Level = 1
                            MemberCount = $memberCount
                        }
                    }
                }
                catch {
                    continue
                }
            }
        }
        
        $script:NestedGroupCache[$GroupDN] = $nestedGroups
    }
    catch {
        $script:NestedGroupCache[$GroupDN] = @()
    }
    
    return $nestedGroups
}

function Get-GroupMemberCount {
    param($Group)
    
    try {
        $groupWithMembers = Get-ADGroup -Identity $Group.DistinguishedName -Properties member -ErrorAction Stop
        $memberDNs = $groupWithMembers.member
        
        if (-not $memberDNs -or $memberDNs.Count -eq 0) {
            return @{
                Success = $true
                Members = @()
                NestedGroups = @()
                Method = "Properties"
            }
        }
        
        $members = @()
        $nestedGroups = @()
        $batchSize = 50
        
        for ($i = 0; $i -lt $memberDNs.Count; $i += $batchSize) {
            $batch = $memberDNs[$i..([Math]::Min($i + $batchSize - 1, $memberDNs.Count - 1))]
            
            foreach ($memberDN in $batch) {
                try {
                    $member = Get-ADObject -Identity $memberDN -Properties objectClass -ErrorAction Stop
                    $members += $member
                    
                    if ($member.objectClass -eq 'group') {
                        $nestedGroups += $member
                    }
                }
                catch {
                    $members += [PSCustomObject]@{
                        DistinguishedName = $memberDN
                        objectClass = 'unknown'
                        Name = "Unknown"
                    }
                }
            }
        }
        
        return @{
            Success = $true
            Members = $members
            NestedGroups = $nestedGroups
            Method = "Batch"
        }
    }
    catch {
        $problemGroups = @('Domain Users', 'Domain Guests', 'Domain Computers', 'Authenticated Users', 'Everyone')
        if ($problemGroups -contains $Group.Name) {
            return @{ Success = $false; Reason = "Skipped built-in group" }
        }
        
        return @{ Success = $false; Reason = "Access denied or group not found" }
    }
}

function Test-UserEnabled {
    param($UserDN)
    
    if ($script:UserStatusCache.ContainsKey($UserDN)) {
        return $script:UserStatusCache[$UserDN]
    }
    
    try {
        $user = Get-ADUser -Identity $UserDN -Properties Enabled -ErrorAction Stop
        $result = @{
            Enabled = $user.Enabled
            Name = $user.Name
            Type = "User"
            Source = "OnPremises"
        }
        $script:UserStatusCache[$UserDN] = $result
        return $result
    }
    catch {
        $result = @{
            Enabled = $null
            Name = "Unknown"
            Type = "User"
            Source = "OnPremises"
        }
        $script:UserStatusCache[$UserDN] = $result
        return $result
    }
}

function Test-ComputerEnabled {
    param($ComputerDN)
    
    if ($script:ComputerStatusCache.ContainsKey($ComputerDN)) {
        return $script:ComputerStatusCache[$ComputerDN]
    }
    
    try {
        $computer = Get-ADComputer -Identity $ComputerDN -Properties Enabled -ErrorAction Stop
        $result = @{
            Enabled = $computer.Enabled
            Name = $computer.Name
            Type = "Computer"
            Source = "OnPremises"
        }
        $script:ComputerStatusCache[$ComputerDN] = $result
        return $result
    }
    catch {
        $result = @{
            Enabled = $null
            Name = "Unknown"
            Type = "Computer"
            Source = "OnPremises"
        }
        $script:ComputerStatusCache[$ComputerDN] = $result
        return $result
    }
}

function Test-GroupHealth {
    param($Group)
    
    $memberResult = Get-GroupMemberCount -Group $Group
    
    if (-not $memberResult.Success) {
        return $null
    }
    
    $nameCompliance = Test-GroupNameCompliance -GroupName $Group.Name
    
    $members = $memberResult.Members
    $nestedGroups = $memberResult.NestedGroups
    $totalMembers = $members.Count

    $allNestedGroups = @()
    if ($nestedGroups.Count -gt 0) {
        $allNestedGroups = $nestedGroups
    }

    $userMembers = @($members | Where-Object { $_.objectClass -eq 'user' })
    $computerMembers = @($members | Where-Object { $_.objectClass -eq 'computer' })
    $groupMembers = @($members | Where-Object { $_.objectClass -eq 'group' })
    $otherMembers = $totalMembers - $userMembers.Count - $computerMembers.Count - $groupMembers.Count

    $nestedGroupNames = ($nestedGroups | ForEach-Object { "$($_.Name) ($($_.MemberCount) members)" }) -join "; "
    
    if ($totalMembers -eq 0) {
        return [PSCustomObject]@{
            GroupName = $Group.Name
            GroupType = $Group.GroupCategory
            GroupScope = $Group.GroupScope
            TotalMembers = 0
            UserMembers = 0
            ComputerMembers = 0
            EnabledUsers = 0
            DisabledUsers = 0
            DisabledUserNames = ""
            EnabledComputers = 0
            DisabledComputers = 0
            DisabledComputerNames = ""
            OtherMembers = 0
            NestedGroupCount = 0
            NestedGroupNames = ""
            NameCompliant = -not $nameCompliance.HasIssues
            NameIssues = $nameCompliance.Issues
            Status = if ($nameCompliance.HasIssues) { "Empty + Name Issues" } else { "Empty" }
            Issue = if ($nameCompliance.HasIssues) { "Group has no members; $($nameCompliance.Issues)" } else { "Group has no members" }
            Recommendation = if ($nameCompliance.HasIssues) { "Consider removing this group; $($nameCompliance.Recommendations)" } else { "Consider removing this group" }
            DistinguishedName = $Group.DistinguishedName
            Source = "OnPremises"
        }
    }

    if ($userMembers.Count -eq 0 -and $computerMembers.Count -eq 0) {
        return [PSCustomObject]@{
            GroupName = $Group.Name
            GroupType = $Group.GroupCategory
            GroupScope = $Group.GroupScope
            TotalMembers = $totalMembers
            UserMembers = 0
            ComputerMembers = 0
            EnabledUsers = 0
            DisabledUsers = 0
            DisabledUserNames = ""
            EnabledComputers = 0
            DisabledComputers = 0
            DisabledComputerNames = ""
            OtherMembers = $otherMembers
            NestedGroupCount = $nestedGroups.Count + $allNestedGroups.Count
            NestedGroupNames = $nestedGroupNames
            NameCompliant = -not $nameCompliance.HasIssues
            NameIssues = $nameCompliance.Issues
            Status = if ($nameCompliance.HasIssues) { "No Users/Computers + Name Issues" } else { "No Users/Computers" }
            Issue = if ($nameCompliance.HasIssues) { "Group contains no user or computer accounts; $($nameCompliance.Issues)" } else { "Group contains no user or computer accounts" }
            Recommendation = if ($nameCompliance.HasIssues) { "Review group membership - may be system/service group; $($nameCompliance.Recommendations)" } else { "Review group membership - may be system/service group" }
            DistinguishedName = $Group.DistinguishedName
            Source = "OnPremises"
        }
    }

    # Check user status efficiently
    $enabledUsers = 0
    $disabledUsers = 0
    $unknownUsers = 0
    $disabledUserNames = @()
    
    foreach ($user in $userMembers) {
        $userInfo = Test-UserEnabled -UserDN $user.DistinguishedName
        switch ($userInfo.Enabled) {
            $true { $enabledUsers++ }
            $false { 
                $disabledUsers++
                $disabledUserNames += $userInfo.Name
            }
            $null { $unknownUsers++ }
        }
    }
    
    # Check computer status efficiently
    $enabledComputers = 0
    $disabledComputers = 0
    $unknownComputers = 0
    $disabledComputerNames = @()
    
    foreach ($computer in $computerMembers) {
        $computerInfo = Test-ComputerEnabled -ComputerDN $computer.DistinguishedName
        switch ($computerInfo.Enabled) {
            $true { $enabledComputers++ }
            $false { 
                $disabledComputers++
                $disabledComputerNames += $computerInfo.Name
            }
            $null { $unknownComputers++ }
        }
    }

    # Determine status with name compliance considerations
    $status = "Healthy"
    $issue = ""
    $recommendation = ""
    
    $totalEnabledAccounts = $enabledUsers + $enabledComputers
    $totalDisabledAccounts = $disabledUsers + $disabledComputers
    $totalUnknownAccounts = $unknownUsers + $unknownComputers
    
    # Primary status determination
    if ($totalEnabledAccounts -eq 0 -and ($totalDisabledAccounts -gt 0 -or $totalUnknownAccounts -gt 0)) {
        $status = "Only Disabled"
        $issue = "Group contains only disabled accounts"
        $recommendation = "Remove disabled accounts or delete group"
    } elseif ($totalDisabledAccounts -gt 0) {
        $status = "Has Disabled"
        $issue = "$disabledUsers disabled user(s) and $disabledComputers disabled computer(s) in group"
        $recommendation = "Remove disabled accounts"
    } elseif ($totalUnknownAccounts -gt 0) {
        $status = "Has Unknown"
        $issue = "$unknownUsers user(s) and $unknownComputers computer(s) could not be verified"
        $recommendation = "Investigate unresolvable accounts"
    }
    
    # Add name compliance issues
    if ($nameCompliance.HasIssues) {
        if ($status -eq "Healthy") {
            $status = "Name Issues"
            $issue = $nameCompliance.Issues
            $recommendation = $nameCompliance.Recommendations
        } else {
            $status += " + Name Issues"
            $issue += "; " + $nameCompliance.Issues
            $recommendation += "; " + $nameCompliance.Recommendations
        }
    }

    return [PSCustomObject]@{
        GroupName = $Group.Name
        GroupType = $Group.GroupCategory
        GroupScope = $Group.GroupScope
        TotalMembers = $totalMembers
        UserMembers = $userMembers.Count
        ComputerMembers = $computerMembers.Count
        EnabledUsers = $enabledUsers
        DisabledUsers = $disabledUsers
        DisabledUserNames = ($disabledUserNames -join "; ")
        EnabledComputers = $enabledComputers
        DisabledComputers = $disabledComputers
        DisabledComputerNames = ($disabledComputerNames -join "; ")
        OtherMembers = $otherMembers
        NestedGroupCount = $nestedGroups.Count + $allNestedGroups.Count
        NestedGroupNames = $nestedGroupNames
        NameCompliant = -not $nameCompliance.HasIssues
        NameIssues = $nameCompliance.Issues
        Status = $status
        Issue = $issue
        Recommendation = $recommendation
        DistinguishedName = $Group.DistinguishedName
        Source = "OnPremises"
    }
}

# Function to create HTML export
function Export-ToHTML {
    param($Results, $FilePath, $DomainName, $IncludesAzureAD = $false, $IncludesOnPremises = $false)
    
    $azureGroups = @($Results | Where-Object { $_.Source -eq "AzureAD" })
    $onPremGroups = @($Results | Where-Object { $_.Source -eq "OnPremises" })
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD Group Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #3498db; }
        .problem-groups { background-color: white; padding: 15px; border-radius: 5px; border-left: 4px solid #e74c3c; }
        .azure-section { border-left: 4px solid #0078d4; margin-bottom: 20px; }
        .onprem-section { border-left: 4px solid #28a745; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; background-color: white; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #34495e; color: white; }
        .azure-header { background-color: #0078d4; }
        .onprem-header { background-color: #28a745; }
        .status-empty { background-color: #fff3cd; color: #856404; }
        .status-disabled { background-color: #f8d7da; color: #721c24; }
        .status-has-disabled { background-color: #d1ecf1; color: #0c5460; }
        .status-healthy { background-color: #d4edda; color: #155724; }
        .nested-groups { font-style: italic; color: #6c757d; max-width: 200px; word-wrap: break-word; }
        .disabled-users { max-width: 200px; word-wrap: break-word; }
        .disabled-none { color: #155724; }
        .disabled-found { color: #dc3545; }
        .group-name { font-weight: bold; color: #2c3e50; }
        .source-badge { padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
        .azure-badge { background-color: #0078d4; color: white; }
        .onprem-badge { background-color: #28a745; color: white; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-box { background-color: white; padding: 15px; border-radius: 5px; text-align: center; flex: 1; }
        .stat-number { font-size: 24px; font-weight: bold; color: #2c3e50; }
        .stat-label { color: #7f8c8d; }
        .environment-split { display: flex; gap: 20px; margin-bottom: 20px; }
        .env-stats { flex: 1; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Active Directory Group Audit Report</h1>
        <p>Domain: $DomainName | Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>Environments: $(if ($IncludesOnPremises) { "On-Premises AD" } else { "" })$(if ($IncludesOnPremises -and $IncludesAzureAD) { " + " } else { "" })$(if ($IncludesAzureAD) { "Azure AD" } else { "" })</p>
    </div>
"@

    if ($IncludesOnPremises -and $IncludesAzureAD) {
        $html += @"
    <div class="environment-split">
        <div class="env-stats">
            <h3 style="color: #28a745;">On-Premises AD</h3>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">$($onPremGroups.Count)</div>
                    <div class="stat-label">Total Groups</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">$(($onPremGroups | Where-Object { $_.Status -ne "Healthy" }).Count)</div>
                    <div class="stat-label">Problem Groups</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">$(($onPremGroups | Where-Object { $_.Status -like "*Empty*" }).Count)</div>
                    <div class="stat-label">Empty Groups</div>
                </div>
            </div>
        </div>
        <div class="env-stats">
            <h3 style="color: #0078d4;">Azure AD</h3>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">$($azureGroups.Count)</div>
                    <div class="stat-label">Total Groups</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">$(($azureGroups | Where-Object { $_.Status -ne "Healthy" }).Count)</div>
                    <div class="stat-label">Problem Groups</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">$(($azureGroups | Where-Object { $_.Status -like "*Empty*" }).Count)</div>
                    <div class="stat-label">Empty Groups</div>
                </div>
            </div>
        </div>
    </div>
"@
    } else {
        $html += @"
    <div class="stats">
        <div class="stat-box">
            <div class="stat-number">$($Results.Count)</div>
            <div class="stat-label">Total Groups</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">$(($Results | Where-Object { $_.Status -ne "Healthy" }).Count)</div>
            <div class="stat-label">Problem Groups</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">$(($Results | Where-Object { $_.Status -like "*Empty*" }).Count)</div>
            <div class="stat-label">Empty Groups</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">$(($Results | Where-Object { $_.Status -like "*Only Disabled*" }).Count)</div>
            <div class="stat-label">Only Disabled</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">$(($Results | Where-Object { $_.Status -like "*Name Issues*" }).Count)</div>
            <div class="stat-label">Name Issues</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">$(($Results | Where-Object { $_.NestedGroupCount -gt 0 }).Count)</div>
            <div class="stat-label">With Nested Groups</div>
        </div>
    </div>
"@
    }
$html += @"
    <div class="problem-groups">
        <h2>Detailed Group Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Group Name</th>
                    <th>Status</th>
                    <th>Total Members</th>
                    <th>Users (E/D)</th>
                    <th>Computers (E/D)</th>
                    <th>Disabled Users</th>
                    <th>Disabled Computers</th>
                    <th>Name Compliant</th>
                    <th>Nested Groups</th>
                    <th>Issue</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($result in ($Results | Sort-Object Source, Status, GroupName)) {
        $statusClass = switch -Wildcard ($result.Status) {
            "*Empty*" { "status-empty" }
            "*Only Disabled*" { "status-disabled" }
            "*Has Disabled*" { "status-has-disabled" }
            "*Name Issues*" { "status-empty" }
            default { "status-healthy" }
        }
        
        $sourceClass = if ($result.Source -eq "AzureAD") { "azure-badge" } else { "onprem-badge" }
        $sourceName = if ($result.Source -eq "AzureAD") { "Azure AD" } else { "On-Prem" }
        
        $nestedGroupsDisplay = if ($result.NestedGroupNames) { $result.NestedGroupNames } else { "None" }
        $disabledUsersDisplay = if ($result.DisabledUserNames) { $result.DisabledUserNames } else { "None" }
        $disabledComputersDisplay = if ($result.DisabledComputerNames) { $result.DisabledComputerNames } else { "None" }
        $nameCompliantDisplay = if ($result.NameCompliant) { "✓ Yes" } else { "✗ No: $($result.NameIssues)" }
        
        $disabledUsersClass = if ($result.DisabledUserNames) { "disabled-found" } else { "disabled-none" }
        $disabledComputersClass = if ($result.DisabledComputerNames) { "disabled-found" } else { "disabled-none" }
        
        $html += @"
                <tr>
                    <td><span class="source-badge $sourceClass">$sourceName</span></td>
                    <td class="group-name">$($result.GroupName)</td>
                    <td class="$statusClass">$($result.Status)</td>
                    <td>$($result.TotalMembers)</td>
                    <td>$($result.EnabledUsers)/$($result.DisabledUsers)</td>
                    <td>$($result.EnabledComputers)/$($result.DisabledComputers)</td>
                    <td class="$disabledUsersClass">$disabledUsersDisplay</td>
                    <td class="$disabledComputersClass">$disabledComputersDisplay</td>
                    <td class="$(if ($result.NameCompliant) { "status-healthy" } else { "status-empty" })">$nameCompliantDisplay</td>
                    <td class="nested-groups">$nestedGroupsDisplay</td>
                    <td>$($result.Issue)</td>
                    <td>$($result.Recommendation)</td>
                </tr>
"@
    }

    $html += @"
            </tbody>
        </table>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $FilePath -Encoding UTF8
}

# Main execution
Show-Banner

# Determine audit scope
$auditAzure = $AzureADOnly -or $IncludeBoth
$auditOnPremises = $OnPremisesOnly -or $IncludeBoth -or (-not $AzureADOnly -and -not $OnPremisesOnly -and -not $IncludeBoth)

Write-Host "Audit Scope:" -ForegroundColor Yellow
if ($auditOnPremises) { Write-Host "  ✓ On-Premises Active Directory" -ForegroundColor Green }
if ($auditAzure) { Write-Host "  ✓ Azure Active Directory" -ForegroundColor Green }
Write-Host ""

# Check and import required modules
if (-not (Test-RequiredModules -IncludeAzure $auditAzure -OnPremisesOnly $OnPremisesOnly)) {
    Write-Host "❌ Required modules not available. Cannot continue." -ForegroundColor Red
    exit 1
}

try {
    $allResults = @()
    $domainName = "Multiple Environments"
    
    # Process on-premises AD
    if ($auditOnPremises -and $script:HasOnPremAD) {
        Write-Host "=== ON-PREMISES ACTIVE DIRECTORY ===" -ForegroundColor Green
        
        # Get domain info
        $domain = Get-ADDomain -ErrorAction SilentlyContinue
        $onPremDomainName = if ($domain) { $domain.DNSRoot } else { "Unknown" }
        if ($domainName -eq "Multiple Environments") {
            $domainName = $onPremDomainName
        } else {
            $domainName = "$domainName + $onPremDomainName"
        }
        Write-Host "Domain: $onPremDomainName" -ForegroundColor Green
        
        # Build filter and get groups
        $filter = "GroupCategory -eq 'Security' -or GroupCategory -eq 'Distribution'"
        
        $getGroupParams = @{
            Filter = $filter
            Properties = @('Name', 'GroupCategory', 'GroupScope', 'DistinguishedName')
        }
        
        if ($SearchBase) {
            $getGroupParams.SearchBase = $SearchBase
            Write-Host "Search Base: $SearchBase" -ForegroundColor Yellow
        }
        
        Write-Host "Retrieving on-premises groups..." -ForegroundColor Yellow
        $onPremGroups = Get-ADGroup @getGroupParams | Where-Object { 
            $_.Name -notin @('Domain Users', 'Domain Guests', 'Domain Computers', 'Authenticated Users', 'Everyone')
        }
        Write-Host "Found $($onPremGroups.Count) on-premises groups to analyze" -ForegroundColor Green
        
        if ($onPremGroups.Count -gt 0) {
            Write-Host "Analyzing on-premises groups..." -ForegroundColor Yellow
            $processed = 0
            $startTime = Get-Date
            $lastChunkEndTime = $startTime  # Initialize here
            
            foreach ($group in $onPremGroups) {
                $processed++
                
                if ($ShowProgress) {
                    $percent = [math]::Round(($processed / $onPremGroups.Count) * 100, 1)
                    Write-Progress -Activity "Analyzing On-Premises Groups" -Status "$($group.Name)" -PercentComplete $percent
                }
                
                $result = Test-GroupHealth -Group $group
                if ($result) {
                    $allResults += $result
                }
                
                # Show periodic progress with cache statistics
                if ($processed % 50 -eq 0) {
                    $currentTime = Get-Date
                    $elapsed = $currentTime - $startTime
                    $rate = [math]::Round($processed / $elapsed.TotalSeconds, 1)
                    
                    if ($processed -eq 50) {
                        # First report - no cache stats yet
                        $chunkTime = $elapsed.TotalSeconds
                        Write-Host "  Processed $processed groups ($rate groups/sec, took $([math]::Round($chunkTime, 1))s)" -ForegroundColor Gray
                        $lastChunkEndTime = $currentTime
                    } else {
                        # Subsequent reports - show cache stats
                        $chunkTime = ($currentTime - $lastChunkEndTime).TotalSeconds
                        $userCacheSize = $script:UserStatusCache.Count
                        $compCacheSize = $script:ComputerStatusCache.Count
                        Write-Host "  Processed $processed groups ($rate groups/sec, chunk took $([math]::Round($chunkTime, 1))s) [Cache: $userCacheSize users, $compCacheSize computers]" -ForegroundColor Gray
                        $lastChunkEndTime = $currentTime
                    }
                }
            }
            
            if ($ShowProgress) {
                Write-Progress -Activity "Analyzing On-Premises Groups" -Completed
            }
        }
    }
    
    # Process Azure AD
    if ($auditAzure -and $script:HasAzureAD) {
        Write-Host "`n=== AZURE ACTIVE DIRECTORY ===" -ForegroundColor Blue
        
        # Connect to Azure AD
        if (-not (Connect-ToAzureAD -TenantId $TenantId)) {
            Write-Host "❌ Failed to connect to Azure AD. Skipping Azure AD audit." -ForegroundColor Red
        } else {
            try {
                # Get Azure AD groups
                Write-Host "Retrieving Azure AD groups..." -ForegroundColor Yellow
                
                if ($script:AzureModule -eq "Graph") {
                    $azureGroups = Get-MgGroup -All -Property "Id,DisplayName,GroupTypes" -ErrorAction Stop
                } else {
                    $azureGroups = Get-AzureADGroup -All $true -ErrorAction Stop
                }
                
                Write-Host "Found $($azureGroups.Count) Azure AD groups to analyze" -ForegroundColor Green
                
                if ($azureGroups.Count -gt 0) {
                    Write-Host "Analyzing Azure AD groups..." -ForegroundColor Yellow
                    $processed = 0
                    $startTime = Get-Date
                    $lastChunkEndTime = $startTime  # Initialize timing variable for Azure AD
                    
                    foreach ($group in $azureGroups) {
                        $processed++
                        
                        if ($ShowProgress) {
                            $percent = [math]::Round(($processed / $azureGroups.Count) * 100, 1)
                            $groupName = if ($script:AzureModule -eq "Graph") { $group.DisplayName } else { $group.DisplayName }
                            Write-Progress -Activity "Analyzing Azure AD Groups" -Status "$groupName" -PercentComplete $percent
                        }
                        
                        $result = Test-AzureADGroupHealth -Group $group
                        if ($result) {
                            $allResults += $result
                        }
                        
                        # Show periodic progress with Azure AD cache statistics
                        if ($processed % 25 -eq 0) {
                            $currentTime = Get-Date
                            $elapsed = $currentTime - $startTime
                            $rate = [math]::Round($processed / $elapsed.TotalSeconds, 1)
                            
                            if ($processed -eq 25) {
                                # First report - no cache stats yet
                                $chunkTime = $elapsed.TotalSeconds
                                Write-Host "  Processed $processed groups ($rate groups/sec, took $([math]::Round($chunkTime, 1))s)" -ForegroundColor Gray
                                $lastChunkEndTime = $currentTime
                            } else {
                                # Subsequent reports - show Azure AD cache stats
                                $chunkTime = ($currentTime - $lastChunkEndTime).TotalSeconds
                                $azureUserCacheSize = $script:AzureUserCache.Count
                                
                                # Count Azure AD nested group cache entries
                                $azureNestedGroupCacheSize = ($script:NestedGroupCache.Keys | Where-Object { $_ -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' }).Count
                                
                                Write-Host "  Processed $processed groups ($rate groups/sec, chunk took $([math]::Round($chunkTime, 1))s) [Cache: $azureUserCacheSize users, $azureNestedGroupCacheSize nested groups]" -ForegroundColor Gray
                                $lastChunkEndTime = $currentTime
                            }
                        }
                    }
                    
                    if ($ShowProgress) {
                        Write-Progress -Activity "Analyzing Azure AD Groups" -Completed
                    }
                }
            }
            catch {
                Write-Host "❌ Error retrieving Azure AD groups: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    
    # Calculate and display results
    if ($allResults.Count -eq 0) {
        Write-Host "`n❌ No groups found or analyzed successfully" -ForegroundColor Red
        exit
    }
    
    $problemGroups = $allResults | Where-Object { $_.Status -ne "Healthy" }
    $emptyGroups = $allResults | Where-Object { $_.Status -like "*Empty*" }
    $disabledOnlyGroups = $allResults | Where-Object { $_.Status -like "*Only Disabled*" }
    $nameIssueGroups = $allResults | Where-Object { $_.Status -like "*Name Issues*" }
    $groupsWithNested = $allResults | Where-Object { $_.NestedGroupCount -gt 0 }
    
    # Environment-specific counts
    $onPremResults = @($allResults | Where-Object { $_.Source -eq "OnPremises" })
    $azureResults = @($allResults | Where-Object { $_.Source -eq "AzureAD" })
    
    # Display summary
    Write-Host "`n" + ("="*80) -ForegroundColor Green
    Write-Host "                        ANALYSIS COMPLETE" -ForegroundColor Green
    Write-Host ("="*80) -ForegroundColor Green
    
    if ($onPremResults.Count -gt 0 -and $azureResults.Count -gt 0) {
        Write-Host "COMBINED RESULTS:" -ForegroundColor White
        Write-Host "  On-Premises Groups: $($onPremResults.Count)" -ForegroundColor Green
        Write-Host "  Azure AD Groups: $($azureResults.Count)" -ForegroundColor Blue
        Write-Host "  Total Groups: $($allResults.Count)" -ForegroundColor White
        Write-Host ""
        Write-Host "PROBLEM ANALYSIS:" -ForegroundColor Red
        Write-Host "  On-Premises Problems: $(($onPremResults | Where-Object { $_.Status -ne "Healthy" }).Count)" -ForegroundColor Yellow
        Write-Host "  Azure AD Problems: $(($azureResults | Where-Object { $_.Status -ne "Healthy" }).Count)" -ForegroundColor Yellow
    } else {
        $environment = if ($onPremResults.Count -gt 0) { "On-Premises" } else { "Azure AD" }
        Write-Host "$environment RESULTS:" -ForegroundColor White
    }
    
    Write-Host "Total Groups Analyzed: $($allResults.Count)" -ForegroundColor White
    Write-Host "Problem Groups Found: $($problemGroups.Count)" -ForegroundColor Red
    Write-Host "  - Empty Groups: $($emptyGroups.Count)" -ForegroundColor Yellow
    Write-Host "  - Only Disabled Users: $($disabledOnlyGroups.Count)" -ForegroundColor Red
    Write-Host "  - Name Issues: $($nameIssueGroups.Count)" -ForegroundColor Magenta
    Write-Host "Groups with Nested Groups: $($groupsWithNested.Count)" -ForegroundColor Cyan
    Write-Host ("="*80) -ForegroundColor Green
    
    # Show problem groups
    if ($problemGroups.Count -gt 0) {
        Write-Host "`nPROBLEM GROUPS:" -ForegroundColor Red
        Write-Host ("─" * 50) -ForegroundColor White
        
        foreach ($group in $problemGroups | Sort-Object Source, Status, GroupName) {
            $statusColor = switch -Wildcard ($group.Status) {
                "*Empty*" { "Yellow" }
                "*Only Disabled*" { "Red" }
                "*Has Disabled*" { "Magenta" }
                "*Name Issues*" { "DarkMagenta" }
                default { "White" }
            }
            
            $sourceColor = if ($group.Source -eq "AzureAD") { "Blue" } else { "Green" }
            $sourceName = if ($group.Source -eq "AzureAD") { "[Azure AD]" } else { "[On-Prem]" }
            
            Write-Host "$sourceName $($group.GroupName)" -ForegroundColor $sourceColor
            Write-Host "  Status: $($group.Status)" -ForegroundColor $statusColor
            Write-Host "  Members: $($group.TotalMembers) total, $($group.UserMembers) users" -ForegroundColor White
            if ($group.ComputerMembers -gt 0) {
                Write-Host "  Computers: $($group.ComputerMembers)" -ForegroundColor White
            }
            if ($group.NestedGroupCount -gt 0) {
                Write-Host "  Nested Groups: $($group.NestedGroupCount)" -ForegroundColor Cyan
            }
            if (-not $group.NameCompliant) {
                Write-Host "  Name Issues: $($group.NameIssues)" -ForegroundColor DarkMagenta
            }
            Write-Host "  Issue: $($group.Issue)" -ForegroundColor Red
            Write-Host "  Action: $($group.Recommendation)" -ForegroundColor Yellow
            Write-Host ""
        }
    } else {
        Write-Host "`n✅ No problem groups found - all groups are healthy!" -ForegroundColor Green
    }
    
    # Export CSV if requested
    if ($ExportPath) {
        Write-Host "Exporting results to CSV: $ExportPath" -ForegroundColor Yellow
        
        try {
            $exportData = @()
            foreach ($result in $allResults) {
                $exportData += [PSCustomObject]@{
                    Source = [string]$result.Source
                    GroupName = [string]$result.GroupName
                    GroupType = [string]$result.GroupType
                    GroupScope = [string]$result.GroupScope
                    TotalMembers = [int]$result.TotalMembers
                    UserMembers = [int]$result.UserMembers
                    ComputerMembers = [int]$result.ComputerMembers
                    EnabledUsers = [int]$result.EnabledUsers
                    DisabledUsers = [int]$result.DisabledUsers
                    DisabledUserNames = [string]($result.DisabledUserNames -replace ';', '|')
                    EnabledComputers = [int]$result.EnabledComputers
                    DisabledComputers = [int]$result.DisabledComputers
                    DisabledComputerNames = [string]($result.DisabledComputerNames -replace ';', '|')
                    OtherMembers = [int]$result.OtherMembers
                    NestedGroupCount = [int]$result.NestedGroupCount
                    NestedGroupNames = [string]($result.NestedGroupNames -replace ';', '|')
                    NameCompliant = [string]$result.NameCompliant
                    NameIssues = [string]($result.NameIssues -replace ';', '|')
                    Status = [string]$result.Status
                    Issue = [string]$result.Issue
                    Recommendation = [string]$result.Recommendation
                    DistinguishedName = [string]$result.DistinguishedName
                }
            }
            
            $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Host "✅ CSV Export completed" -ForegroundColor Green
        }
        catch {
            Write-Host "❌ CSV Export failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Export HTML if requested
    if ($ExportHTML) {
        Write-Host "Exporting results to HTML: $ExportHTML" -ForegroundColor Yellow
        Export-ToHTML -Results $allResults -FilePath $ExportHTML -DomainName $domainName -IncludesAzureAD ($azureResults.Count -gt 0) -IncludesOnPremises ($onPremResults.Count -gt 0)
        Write-Host "✅ HTML Export completed" -ForegroundColor Green
    }
    
}
catch {
    Write-Host "`n❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Gray
    exit 1
}

Write-Host "`nAudit completed successfully!" -ForegroundColor Green

# Additional Azure AD specific notes
if ($auditAzure -and $script:HasAzureAD) {
    Write-Host "`nAZURE AD NOTES:" -ForegroundColor Blue
    Write-Host "- Computer objects don't exist in Azure AD (cloud-only environment)" -ForegroundColor Gray
    Write-Host "- Group scopes may show as 'Unknown' for Azure AD groups" -ForegroundColor Gray
    Write-Host "- Nested group analysis limited to direct children for performance" -ForegroundColor Gray
    
    if ($script:AzureModule -eq "AzureAD") {
        Write-Host "- Consider upgrading to Microsoft.Graph modules for better performance and future support" -ForegroundColor Yellow
    }
}
