#Requires -Version 7

<#PSScriptInfo

.VERSION 1.1.0

.GUID 3b9c9df5-3b5f-4c1a-9a6c-097be91fa292

.AUTHOR Amir Joseph Sayes

.COMPANYNAME amirsayes.co.uk

.COPYRIGHT (c) 2025. All rights reserved.

.TAGS Intune Configuration Management Microsoft Graph Azure

.LICENSEURI https://github.com/amirjs/Get-IntuneAssignments/blob/main/LICENSE

.PROJECTURI https://github.com/amirjs/Get-IntuneAssignments/tree/main

.ICONURI

.EXTERNALMODULEDEPENDENCIES 
Microsoft.Graph.Authentication

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
v1.1.0 - June 2026:
        - Eliminated all Microsoft Graph Beta SDK module dependencies except Microsoft.Graph.Authentication
        - All policy retrieval now uses direct Invoke-MgGraphRequest calls (no SDK cmdlets)
        - Added Invoke-GraphPaginated and Get-FilterSuffix helper functions
        - Simplified and unified assignment-loop logic across all functions
        - Added support for App Configuration Policies (Managed Devices) assignments
        - Added support for iOS LoB App Provisioning Configuration assignments        
v1.0.15 - May 2026:
        - Added support for Terms and Conditions assignments
        - Added support for new-style Compliance Policies (Settings Catalog-based)
        - Added support for Cloud PC Provisioning Policy assignments
        - Added support for WDAC Supplemental Policy assignments
        - Added support for macOS Shell Script assignments
        - Added support for macOS Custom Attribute Shell Script assignments
        - Added support for Intune Branding Profile assignments
v1.0.14 - November 2025:
        - Fixed: Added missing DeviceManagementRBAC.Read.All permission for Intune Role Assignments
        - Fixed: Removed unnecessary Directory.Read.All permission from documentation
        - Improved: Cleaned up PSScriptInfo metadata following PowerShell best practices
v1.0.13 - November 2025:
        - Fixed: Duplicate output when running script without parameters
        - Fixed: SystemManagedIdentity authentication parameter validation error
v1.0.12 - November 2025:
        - Added support for Intune Role Assignments
        - Added support for Cloud PC Role Assignments
        - Added CloudPC.Read.All permission to Graph scopes
        - Added support for Device Enrollment Configurations
        - Fixed Out-GridView compatibility - script now returns PowerShell objects instead of formatting objects
        - Results can now be used with Out-GridView, Export-Csv, and other PowerShell cmdlets
v1.0.11 - 2025:
        - Added support for Windows Update Policies (Quality Updates, Feature Updates, Update Rings, Driver Updates)
v1.0.10 - 2025:
        - Added support for certificate-based authentication (thumbprint)
        - Added support for client secret authentication
        - Added support for managed identity authentication (user-assigned and system-assigned)
v1.0.9 - 2025:
        - Fixed bug with group names containing spaces
        - Added logic to handle multiple groups matching search criteria
v1.0.7 - 2025:
        - Enhanced function capabilities
v1.0.1 - Initial Release:
        - Get all Intune Configuration Profile assignments
        - Support for Device Configuration, Compliance Policies, Security Baselines, Apps, and more
#>

<#
.SYNOPSIS
    Retrieves all Intune Configuration Profile assignments.


.DESCRIPTION
    This script retrieves assignments and filters for various Intune configuration types including:
    - Device Configuration Profiles
    - Device Management Configuration Policies
    - Compliance Policies
    - Security Baselines
    - Administrative Templates
    - App Protection Policies
    - Apps Assignments
    - Windows Information Protection Policies
    - Remediation Scripts
    - Device Management Scripts
    - Autopilot Profiles (v1)
    - Device Enrollment Configurations
    - Role Assignments
    - Cloud PC Role Assignments
    - Windows Update Policies:
      * Windows Quality Update Profiles
      * Windows Feature Update Profiles
      * Windows Update Rings
      * Windows Driver Update Profiles
    - Terms and Conditions
    - Compliance Policies (new Settings Catalog-based)
    - Cloud PC Provisioning Policies
    - WDAC Supplemental Policies
    - macOS Shell Scripts
    - macOS Custom Attribute Shell Scripts
    - Intune Branding Profiles
    - App Configuration Policies (Managed Devices)
    - iOS LoB App Provisioning Configurations
    
    Required Microsoft Graph API permissions:
    - DeviceManagementConfiguration.Read.All
    - DeviceManagementApps.Read.All
    - DeviceManagementManagedDevices.Read.All
    - DeviceManagementServiceConfig.Read.All
    - Group.Read.All
    - DeviceManagementRBAC.Read.All (for Intune Role Assignments)
    - CloudPC.Read.All (for Cloud PC Role Assignments and Cloud PC Provisioning Policies)
    - DeviceManagementServiceConfig.Read.All (for Terms and Conditions)
    - DeviceManagementScripts.Read.All (for macOS Shell Scripts and Custom Attribute Scripts)

    - Shows included and excluded groups for each assignment
    - Displays filter information if configured
    - Export results to CSV
    - Filter by specific Azure AD group

.PARAMETER OutputFile
    Path to export the results as CSV. If not specified, results will be displayed in console.

.PARAMETER GroupName
    Name of the Azure AD group to filter assignments. Only assignments that include or exclude this group will be returned.

.PARAMETER AuthMethod
    Authentication method to use when connecting to Microsoft Graph. Valid values are:
    - Interactive (default)
    - Certificate
    - ClientAppAccess
    - UserManagedIdentity
    - SystemManagedIdentity

.PARAMETER TenantId
    The Azure AD tenant ID to connect to.

.PARAMETER ClientId
    The client ID (application ID) to use for certificate or managed identity authentication.


.PARAMETER CertificateThumbprint
    The thumbprint of the certificate to use for authentication. Requires ClientId and TenantId. Only thumbprint-based authentication is supported; CertificatePath is not supported.

.PARAMETER ClientSecretCredential
    A PSCredential object containing the client secret credential information.
    Username should be the ClientId, and Password should be the ClientSecret.
    This is the recommended way to use client secret authentication.


.EXAMPLE
    Get-IntuneAssignments
    Returns all Intune configuration assignments and displays them in the console using interactive authentication.

.EXAMPLE
    Get-IntuneAssignments -OutputFile "C:\temp\assignments.csv"
    Retrieves all assignments using interactive authentication and exports them to the specified CSV file.

.EXAMPLE
    Get-IntuneAssignments -GroupName "Pilot Users"
    Returns assignments that include or exclude the specified group using interactive authentication.

.EXAMPLE
    $assignments = Get-IntuneAssignments
    $assignments | Out-GridView
    Retrieves all assignments and displays them in an interactive grid view for filtering and sorting.

.EXAMPLE
    $assignments = Get-IntuneAssignments
    $assignments | Where-Object { $_.ProfileType -like "*enrollment*" } | Out-GridView
    Retrieves all assignments, filters for enrollment configurations, and displays them in grid view.

.EXAMPLE
    Get-IntuneAssignments -AuthMethod Interactive -TenantId "contoso.onmicrosoft.com"
    Connects interactively to a specific tenant.

.EXAMPLE
    # Certificate authentication (thumbprint, app registration with certificate in store)
    Get-IntuneAssignments -AuthMethod Certificate -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678"
    Connects using certificate authentication with a certificate thumbprint.

.EXAMPLE
    # Client secret authentication
    $credential = New-Object System.Management.Automation.PSCredential("12345678-1234-1234-1234-123456789012", (ConvertTo-SecureString "YourClientSecret" -AsPlainText -Force))
    Get-IntuneAssignments -AuthMethod ClientSecret -TenantId "contoso.onmicrosoft.com" -ClientSecretCredential $credential
    Connects using client secret authentication with a PSCredential object.

.EXAMPLE
    # User-assigned managed identity authentication
    Get-IntuneAssignments -AuthMethod UserManagedIdentity -TenantId "contoso.onmicrosoft.com" -ClientId "<user-assigned-managed-identity-client-id>"
    Connects using a user-assigned managed identity.

.EXAMPLE
    # System-assigned managed identity authentication
    Get-IntuneAssignments -AuthMethod SystemManagedIdentity -TenantId "contoso.onmicrosoft.com"
    Connects using a system-assigned managed identity.

.EXAMPLE
    # Group filtering and CSV export with certificate authentication
    Get-IntuneAssignments -AuthMethod Certificate -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678" -GroupName "Pilot Users" -OutputFile "C:\temp\PilotUsersAssignments.csv"
    Retrieves assignments for a specific group using certificate authentication and exports to CSV.

.NOTES
    Requirements:   
    - PowerShell 7 or higher
    - Microsoft.Graph.Authentication module (automatically installed if missing)
    - All other Microsoft Graph SDK modules are NOT required; direct API calls are used throughout
    
    For the latest version and updates, visit:
    https://github.com/amirjs/Get-IntuneAssignments
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile,
    
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName,

    # Authentication Parameters    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Interactive', 'Certificate', 'ClientSecret', 'UserManagedIdentity', 'SystemManagedIdentity')]
    [string]$AuthMethod = 'Interactive',

    [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
    [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
    [Parameter(Mandatory = $true, ParameterSetName = 'UserManagedIdentity')]
    [Parameter(Mandatory = $false, ParameterSetName = 'SystemManagedIdentity')]
    [string]$TenantId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
    [Parameter(Mandatory = $false, ParameterSetName = 'ClientSecret')]
    [Parameter(Mandatory = $true, ParameterSetName = 'UserManagedIdentity')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'Certificate')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
    [System.Management.Automation.PSCredential]
    $ClientSecretCredential   
 
)

#region Support Functions

function Invoke-GraphPaginated {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )
    $results = @()
    do {
        $response = Invoke-MgGraphRequest -Uri $Uri -Method Get
        $results += $response.value
        $Uri = $response.'@odata.nextLink'
    } while ($Uri)
    return $results
}

function Get-GroupDisplayNameSafe {
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )
    try {
        $response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$GroupId" -Method Get -ErrorAction Stop
        return $response.displayName
    } catch {
        return "$GroupId (Deleted or Not Found)"
    }
}

function Get-AssignmentFilterName {
    param (
        [Parameter(Mandatory = $false)]
        [string]$FilterId
    )
    if (-not $FilterId -or $FilterId -eq ([guid]::Empty).ToString()) {
        return ""
    }
    try {
        $response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters/$FilterId" -Method Get -ErrorAction Stop
        return " | Filter: $($response.displayName)"
    } catch {
        return ""
    }
}

function Get-FilterSuffix {
    # For included groups: returns the filter name or " | No Filter" if no filter is assigned
    param (
        [Parameter(Mandatory = $false)]
        [string]$FilterId
    )
    $name = Get-AssignmentFilterName -FilterId $FilterId
    return $(if ($name) { $name } else { " | No Filter" })
}

function Get-IntuneAppProtectionAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies?`$filter=displayName eq '$displayName'"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies"
        }
        $allPolicies = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve App Protection Policies: $_"
        return
    }

    foreach ($policy in $allPolicies) {
        $includedGroups = @()
        $excludedGroups = @()

        $odataType = $policy.'@odata.type'
        if ($odataType -eq '#microsoft.graph.androidManagedAppProtection') {
            $assignUri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')/assignments"
        } elseif ($odataType -eq '#microsoft.graph.iosManagedAppProtection') {
            $assignUri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')/assignments"
        } elseif ($odataType -eq '#microsoft.graph.windowsInformationProtectionAppLockerFileProtection') {
            $assignUri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionAppLockerFileProtections('$($policy.id)')/assignments"
        } elseif ($odataType -in @('#microsoft.graph.windowsManagedAppProtection', '#microsoft.graph.windowsManagedAppProtections')) {
            $assignUri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.id)')/assignments"
        } elseif ($odataType -eq '#microsoft.graph.targetedManagedAppConfiguration') {
            $assignUri = "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations('$($policy.id)')/assignments"
        } else {
            Write-Output "No App Protection Policy assignment found for $($policy.displayName)"
            continue
        }

        try {
            $assignments = (Invoke-MgGraphRequest -Uri $assignUri -Headers @{ConsistencyLevel = "eventual"} -ContentType "application/json").value
        } catch { continue }

        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $policy.displayName
                ProfileType    = $odataType -replace '^#microsoft\.graph\.', ''
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneManagedDeviceAppAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$displayName'"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
        }
        $allApps = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Mobile Apps: $_"
        return
    }

    foreach ($app in $allApps) {
        try {
            $assignments = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$($app.id)')/assignments" -Method Get -ErrorAction Stop).value
        } catch { continue }

        if (-not $assignments -or $assignments.Count -eq 0) { continue }

        $includedGroups = @()
        $hasMatchingAssignment = $false

        foreach ($assignment in $assignments) {
            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
                $hasMatchingAssignment = $true
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                if ($groupId) { continue }
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
                $hasMatchingAssignment = $true
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                if ($groupId) { continue }
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
                $hasMatchingAssignment = $true
            }
        }

        if ($hasMatchingAssignment) {
            [PSCustomObject]@{
                DisplayName    = $app.displayName
                ProfileType    = "Mobile App Deployment"
                IncludedGroups = $includedGroups
                ExcludedGroups = $null
            }
        }
    }
}

function Get-IntuneDeviceManagementSecurityBaselineAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/intents?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/intents?`$expand=assignments"
        }
        $allBaselines = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Security Baselines: $_"
        return
    }

    foreach ($baseline in $allBaselines) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $baseline.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            $templateName = $null
            if ($baseline.templateId) {
                try {
                    $tmpl = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$($baseline.templateId)" -Method Get -ErrorAction Stop
                    $templateName = $tmpl.displayName
                } catch {}
            }
            [PSCustomObject]@{
                DisplayName    = $baseline.displayName
                TemplateName   = $templateName
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneDeviceCompliancePolicyAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$expand=assignments"
        }
        $allPolicies = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Device Compliance Policies: $_"
        return
    }

    foreach ($policy in $allPolicies) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $policy.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $policy.displayName
                ProfileType    = $policy.'@odata.type' -replace '^#microsoft\.graph\.', ''
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneDeviceConfigurationAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$expand=assignments"
        }
        $allConfigs = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Device Configurations: $_"
        return
    }

    foreach ($config in $allConfigs) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $config.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $config.displayName
                ProfileType    = $config.'@odata.type' -replace '^#microsoft\.graph\.', ''
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneDeviceManagementConfigurationPolicyAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=name eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$expand=assignments"
        }
        $allPolicies = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Device Management Configuration Policies: $_"
        return
    }

    foreach ($policy in $allPolicies) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $policy.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            $profileType = if ($policy.templateReference.templateDisplayName) {
                $policy.templateReference.templateDisplayName
            } else {
                "Device Management Configuration Policy"
            }
            [PSCustomObject]@{
                DisplayName    = $policy.name
                ProfileType    = $profileType
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneDeviceConfigurationAdministrativeTemplatesAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$expand=assignments"
        }
        $allTemplates = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Administrative Templates: $_"
        return
    }

    foreach ($template in $allTemplates) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $template.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $template.displayName
                ProfileType    = "AdministrativeTemplates"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneRemediationScriptAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$expand=assignments"
        }
        $allScripts = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Remediation Scripts: $_"
        return
    }

    foreach ($script in $allScripts) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $script.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $script.displayName
                ProfileType    = "Remediation Script"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneWindowsUpdateAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    # Windows Quality Update Profiles
    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles?`$expand=assignments"
        }
        $qualityProfiles = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Windows Quality Update Profiles: $_"
        $qualityProfiles = @()
    }

    foreach ($profile in $qualityProfiles) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $profile.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $profile.displayName
                ProfileType    = "Windows Quality Update Profile"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }

    # Windows Feature Update Profiles
    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles?`$expand=assignments"
        }
        $featureProfiles = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Windows Feature Update Profiles: $_"
        $featureProfiles = @()
    }

    foreach ($profile in $featureProfiles) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $profile.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $profile.displayName
                ProfileType    = "Windows Feature Update Profile"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }

    # Windows Update Ring Settings (windowsQualityUpdatePolicies)
    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdatePolicies?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdatePolicies?`$expand=assignments"
        }
        $updateRings = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Windows Update Ring assignments: $_"
        $updateRings = @()
    }

    foreach ($ring in $updateRings) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $ring.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $ring.displayName
                ProfileType    = "Windows Update Ring"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }

    # Windows Driver Update Profiles
    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles?`$expand=assignments"
        }
        $driverProfiles = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Windows Driver Update Profile assignments: $_"
        $driverProfiles = @()
    }

    foreach ($profile in $driverProfiles) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $profile.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $profile.displayName
                ProfileType    = "Windows Driver Update Profile"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneAutopilotProfileAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles?`$expand=assignments"
        }
        $allProfiles = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Autopilot Profiles: $_"
        return
    }

    foreach ($profile in $allProfiles) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $profile.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $profile.displayName
                ProfileType    = "Autopilot Profile"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneDeviceManagementScriptAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$expand=assignments"
        }
        $allScripts = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Device Management Scripts: $_"
        return
    }

    foreach ($script in $allScripts) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $script.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $script.displayName
                ProfileType    = "Device Management Script"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneWindowsInformationProtectionPolicyAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies?`$expand=assignments"
        }
        $allPolicies = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Windows Information Protection Policies: $_"
        return
    }

    foreach ($policy in $allPolicies) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $policy.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $policy.displayName
                ProfileType    = "Windows Information Protection Policy"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneDeviceEnrollmentConfigurationAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations?`$expand=assignments"
        }
        $allConfigs = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Device Enrollment Configurations: $_"
        return
    }

    foreach ($config in $allConfigs) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $config.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $config.displayName
                ProfileType    = $config.'@odata.type' -replace '^#microsoft\.graph\.', ''
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneRoleAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments?`$filter=displayName eq '$displayName'"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments"
        }
        $allRoleAssignments = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Intune Role Assignments: $_"
        return
    }

    foreach ($roleAssignment in $allRoleAssignments) {
        $includedGroups = @()
        $hasMatchingAssignment = $false

        if ($groupId) {
            $isInMembers = $roleAssignment.members -contains $groupId
            $isInScopes  = $roleAssignment.resourceScopes -contains $groupId
            if (-not ($isInMembers -or $isInScopes)) { continue }
            $hasMatchingAssignment = $true
        } else {
            $hasMatchingAssignment = $true
        }

        if ($roleAssignment.members) {
            foreach ($memberId in $roleAssignment.members) {
                $memberName = $null
                try {
                    $memberObj = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$memberId" -Method Get -ErrorAction Stop
                    $memberName = "$($memberObj.displayName) (Member)"
                } catch {
                    try {
                        $memberObj = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/users/$memberId" -Method Get -ErrorAction Stop
                        $memberName = "$($memberObj.displayName) (User)"
                    } catch {
                        $memberName = "$memberId (Member)"
                    }
                }

                if ($roleAssignment.resourceScopes) {
                    foreach ($scopeId in $roleAssignment.resourceScopes) {
                        try {
                            $scopeObj = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$scopeId" -Method Get -ErrorAction Stop
                            $includedGroups += "$memberName | Scope: $($scopeObj.displayName)"
                        } catch {
                            $includedGroups += "$memberName | Scope: $scopeId"
                        }
                    }
                } else {
                    $includedGroups += $memberName
                }
            }
        }

        if ($hasMatchingAssignment -and $includedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $roleAssignment.displayName
                ProfileType    = "Role Assignment"
                IncludedGroups = $includedGroups
                ExcludedGroups = @()
            }
        }
    }
}

function Get-CloudPcRoleAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        $allRoleAssignments = Invoke-GraphPaginated -Uri "https://graph.microsoft.com/beta/roleManagement/cloudPC/roleAssignments"
        if ($displayName) {
            $allRoleAssignments = $allRoleAssignments | Where-Object { $_.displayName -eq $displayName }
        }
    } catch {
        Write-Warning "Failed to retrieve Cloud PC role assignments. This might require additional permissions or the Cloud PC service may not be configured."
        return
    }

    foreach ($roleAssignment in $allRoleAssignments) {
        $includedGroups = @()
        $hasMatchingAssignment = $false

        if ($groupId) {
            $isInPrincipal = $roleAssignment.principalIds -contains $groupId
            $isInScopes    = $roleAssignment.directoryScopeIds -contains $groupId
            if (-not ($isInPrincipal -or $isInScopes)) { continue }
            $hasMatchingAssignment = $true
        } else {
            $hasMatchingAssignment = $true
        }

        $roleName = "Cloud PC Role"
        if ($roleAssignment.roleDefinitionId) {
            try {
                $roleDef = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/roleManagement/cloudPC/roleDefinitions/$($roleAssignment.roleDefinitionId)" -Method Get -ErrorAction Stop
                $roleName = $roleDef.displayName
            } catch {
                $roleName = "Cloud PC Role ($($roleAssignment.roleDefinitionId))"
            }
        }

        if ($roleAssignment.principalIds) {
            foreach ($principalId in $roleAssignment.principalIds) {
                $principalName = $null
                try {
                    $principalObj = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$principalId" -Method Get -ErrorAction Stop
                    $principalName = "$($principalObj.displayName) (Member)"
                } catch {
                    try {
                        $principalObj = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/users/$principalId" -Method Get -ErrorAction Stop
                        $principalName = "$($principalObj.displayName) (User)"
                    } catch {
                        $principalName = "$principalId (Member)"
                    }
                }

                if ($roleAssignment.directoryScopeIds) {
                    foreach ($scopeId in $roleAssignment.directoryScopeIds) {
                        try {
                            $scopeObj = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$scopeId" -Method Get -ErrorAction Stop
                            $includedGroups += "$principalName | Role: $roleName | Scope: $($scopeObj.displayName)"
                        } catch {
                            $includedGroups += "$principalName | Role: $roleName | Scope: $scopeId"
                        }
                    }
                } else {
                    $includedGroups += "$principalName | Role: $roleName"
                }
            }
        }

        if ($hasMatchingAssignment -and $includedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = if ($roleAssignment.displayName) { $roleAssignment.displayName } else { "Cloud PC Role Assignment" }
                ProfileType    = "Cloud PC Role Assignment"
                IncludedGroups = $includedGroups
                ExcludedGroups = @()
            }
        }
    }
}

function Get-IntuneTermsAndConditionsAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/termsAndConditions?`$filter=displayName eq '$displayName'"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/termsAndConditions"
        }
        $allTaC = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Terms and Conditions assignments: $_"
        return
    }

    foreach ($tac in $allTaC) {
        $includedGroups = @()
        $excludedGroups = @()

        try {
            $assignments = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/termsAndConditions/$($tac.id)/assignments" -Method Get -ErrorAction Stop).value
        } catch { continue }

        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $tac.displayName
                ProfileType    = "Terms and Conditions"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneNewCompliancePolicyAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/compliancePolicies?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/compliancePolicies?`$expand=assignments"
        }
        $allPolicies = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve new-style Compliance Policies: $_"
        return
    }

    foreach ($policy in $allPolicies) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $policy.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $policy.name
                ProfileType    = "Compliance Policy (Settings Catalog)"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneCloudPcProvisioningPolicyAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies?`$expand=assignments"
        }
        $allPolicies = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Cloud PC Provisioning Policies: $_"
        return
    }

    foreach ($policy in $allPolicies) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $policy.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.cloudPcManagementGroupAssignmentTarget') {
                $includedGroups += Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId
            } elseif ($assignment.target.'@odata.type' -in @('#microsoft.graph.cloudPcManagementAllDevicesAssignmentTarget', '#microsoft.graph.allDevicesAssignmentTarget')) {
                $includedGroups += "All Devices"
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users"
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $policy.displayName
                ProfileType    = "Cloud PC Provisioning Policy"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneWdacSupplementalPolicyAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/wdacSupplementalPolicies?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/wdacSupplementalPolicies?`$expand=assignments"
        }
        $allPolicies = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve WDAC Supplemental Policies: $_"
        return
    }

    foreach ($policy in $allPolicies) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $policy.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $policy.displayName
                ProfileType    = "WDAC Supplemental Policy"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneMacOsShellScriptAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts?`$expand=assignments"
        }
        $allScripts = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve macOS Shell Scripts: $_"
        return
    }

    foreach ($script in $allScripts) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $script.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $script.displayName
                ProfileType    = "macOS Shell Script"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneMacOsCustomAttributeScriptAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCustomAttributeShellScripts?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCustomAttributeShellScripts?`$expand=assignments"
        }
        $allScripts = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve macOS Custom Attribute Scripts: $_"
        return
    }

    foreach ($script in $allScripts) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $script.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $script.displayName
                ProfileType    = "macOS Custom Attribute Script"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneBrandingProfileAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles?`$filter=displayName eq '$displayName'&`$expand=assignments"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles?`$expand=assignments"
        }
        $allProfiles = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve Intune Branding Profiles: $_"
        return
    }

    foreach ($profile in $allProfiles) {
        $includedGroups = @()
        $excludedGroups = @()

        foreach ($assignment in $profile.assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices"
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users"
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $profile.displayName
                ProfileType    = "Intune Branding Profile"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneMobileAppConfigurationAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations?`$filter=displayName eq '$displayName'"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations"
        }
        $allConfigs = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve App Configuration Policies (Managed Devices): $_"
        return
    }

    foreach ($config in $allConfigs) {
        $includedGroups = @()
        $excludedGroups = @()

        try {
            $assignments = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations('$($config.id)')/assignments" -Method Get -ErrorAction Stop).value
        } catch { continue }

        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $config.displayName
                ProfileType    = "App Configuration Policy (Managed Devices)"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneIosLobAppProvisioningConfigurationAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    try {
        if ($displayName) {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosLobAppProvisioningConfigurations?`$filter=displayName eq '$displayName'"
        } else {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosLobAppProvisioningConfigurations"
        }
        $allConfigs = Invoke-GraphPaginated -Uri $uri
    } catch {
        Write-Warning "Failed to retrieve iOS LoB App Provisioning Configurations: $_"
        return
    }

    foreach ($config in $allConfigs) {
        $includedGroups = @()
        $excludedGroups = @()

        try {
            $assignments = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/iosLobAppProvisioningConfigurations('$($config.id)')/assignments" -Method Get -ErrorAction Stop).value
        } catch { continue }

        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) { continue }

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $includedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $includedGroups += "All Devices" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $includedGroups += "All Users" + (Get-FilterSuffix -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-GroupDisplayNameSafe -GroupId $assignment.target.groupId) + (Get-AssignmentFilterName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId)
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName    = $config.displayName
                ProfileType    = "iOS LoB App Provisioning Configuration"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}
#endregion

#region Module Installation

$requiredModules = @(
    "Microsoft.Graph.Authentication"
)

Write-Host "Checking required modules..." -ForegroundColor Cyan
$modulesNeedingInstall = @()

foreach ($module in $requiredModules) {
    try {        
        $existingModule = Get-Module -Name $module -ListAvailable
        if (-not $existingModule) {
            $modulesNeedingInstall += $module
        }
        else {
            Write-Host "Module $module is already installed (Version: $($existingModule[0].Version))." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Error checking module $module`: $_"
    }
}

if ($modulesNeedingInstall.Count -gt 0) {
    Write-Host "The following modules need to be installed: $($modulesNeedingInstall -join ', ')" -ForegroundColor Yellow
    $userConsent = Read-Host "Do you want to proceed with installing the required modules? (Y/N)"
    if ($userConsent -match '^[Yy]$') {
        Write-Host "Installing required modules..." -ForegroundColor Cyan
        foreach ($module in $modulesNeedingInstall) {
            try {
                Write-Host "Installing $module..." -ForegroundColor Yellow
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                Write-Host "Successfully installed $module" -ForegroundColor Green
            } catch {
                Write-Error "Failed to install module $module. Error: $_"
                return
            }
        }
    } else {
        Write-Host "Module installation canceled by user. Exiting script." -ForegroundColor Red
        return
    }
}

# Import all required modules
foreach ($module in $requiredModules) {
    try {
        # if module is not already loaded, import it
        if (-not (Get-Module -Name $module)) {
            Write-Host "Importing $module..." -ForegroundColor Yellow
            Import-Module -Name $module -Force -ErrorAction Stop
            write-host "Successfully imported $module" -ForegroundColor Green
        } else {
            Write-Host "$module is already loaded." -ForegroundColor Green
            continue
        }
    } catch {
        Write-Error "Failed to import module $module. Error: $_"
        return    }
}
#endregion

# Connect to Microsoft Graph if not already connected
try {
    if (-not (Get-MgContext)) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        
        $connectParams = @{
            NoWelcome = $true
        }

        switch ($AuthMethod) {
            'Interactive' {
                if ($TenantId) { $connectParams['TenantId'] = $TenantId }
                Connect-MgGraph @connectParams -Scopes "DeviceManagementServiceConfig.Read.All","DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementApps.Read.All", "Group.Read.All", "DeviceManagementRBAC.Read.All", "CloudPC.Read.All"
            }
            'Certificate' {
                if (-not $CertificateThumbprint) {
                    throw "CertificateThumbprint must be provided for certificate authentication. CertificatePath is not supported."
                }

                $connectParams += @{
                    ClientId = $ClientId
                    TenantId = $TenantId
                    CertificateThumbprint = $CertificateThumbprint
                }
                Write-Verbose "Using certificate authentication (thumbprint only)"
                Connect-MgGraph @connectParams
            }
            'ClientSecret' {
                # Check if ClientSecretCredential is provided
                if (-not($ClientSecretCredential -and $TenantId)) {
                    throw "Both ClientSecretCredential object (which contains ClientID and ClientSecret) and TenantId must be provided for client secret authentication"
                }
                
                $connectParams += @{
                    TenantId = $TenantId
                    ClientSecretCredential = $ClientSecretCredential
                }
                
                Write-Verbose "Using client secret authentication with credentials"
                Connect-MgGraph @connectParams
            }
            'UserManagedIdentity' {
                $connectParams += @{
                    Identity = $true
                    TenantId = $TenantId
                    ClientId = $ClientId
                }
                Write-Verbose "Using user-assigned managed identity authentication"
                Connect-MgGraph @connectParams
            }
            'SystemManagedIdentity' {
                $connectParams += @{
                    Identity = $true
                }
                if ($TenantId) {
                    $connectParams['TenantId'] = $TenantId
                }
                Write-Verbose "Using system-assigned managed identity authentication"
                Connect-MgGraph @connectParams
            }           
        }

        $context = Get-MgContext
        if (-not $context) {
            throw "Failed to establish Microsoft Graph connection"
        }
        
        if ($context.ManagedIdentityId) {
            Write-Host "Successfully connected to Microsoft Graph using Managed Identity: $($context.ManagedIdentityId)" -ForegroundColor Green
        } elseif ($context.Account) {
            Write-Host "Successfully connected to Microsoft Graph as: $($context.Account)" -ForegroundColor Green
        } elseif ($context.AppName) {
            Write-Host "Successfully connected to Microsoft Graph using Client ID: $($context.ClientId) and Application Name: $($context.AppName)" -ForegroundColor Green
        } else {
            Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
        }
                
        Write-Host "Scopes: $($context.Scopes -join ', ')" -ForegroundColor Yellow
    }
    else {
        if ($AuthMethod -eq 'UserManagedIdentity' -or $AuthMethod -eq 'SystemManagedIdentity') {
            Write-Host "Already connected to Microsoft Graph as: $((Get-MgContext).ManagedIdentityId)" -ForegroundColor Green
            write-host "Scope: $((Get-MgContext).Scopes)" -ForegroundColor Green
        } else {
            Write-Host "Already connected to Microsoft Graph as: $((Get-MgContext).Account)" -ForegroundColor Green
            write-host "Scope: $((Get-MgContext).Scopes)" -ForegroundColor Green
        }
    }
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    return
}

# Initialize results array
$results = @()

# Get group ID if GroupName is provided
$groupId = $null
if ($GroupName) {
    try {
        $groupResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups?`$search=`"displayName:$GroupName`"&`$count=true&`$select=id,displayName" -Headers @{ConsistencyLevel = "eventual"} -Method Get
        $group = $groupResponse.value
        $c = $groupResponse.'@odata.count'
        if (-not $group -or $group.Count -eq 0) {
            Write-Error "Group '$GroupName' not found."
            return
        }
        # If more than one group found, prompt user to select one
        if ($c -gt 1 -or $group.Count -gt 1) {
            Write-Host "Multiple groups found. Please select one:" -ForegroundColor Yellow
            $group | ForEach-Object { Write-Host "$($_.id): $($_.displayName)" -ForegroundColor Cyan }
            $selectedGroupId = Read-Host "Enter the ID of the group you want to use"
            $groupId = ($group | Where-Object { $_.id -eq $selectedGroupId }).id
            $groupDisplayName = ($group | Where-Object { $_.id -eq $selectedGroupId }).displayName
            if (-not $groupId) {
                Write-Error "Invalid group ID selected."
                return
            }
        } else {
            $groupId = $group[0].id
            $groupDisplayName = $group[0].displayName
        }
        Write-Host "Processing assignments for group: $groupDisplayName and ID: $groupId" -ForegroundColor Green
    } catch {
        Write-Error "Failed to get group information: $_"
        return
    }
}

$processSteps = @(
    @{ Name = "App Protection Policies"; Function = "Get-IntuneAppProtectionAssignment" },
    @{ Name = "Managed Device Apps"; Function = "Get-IntuneManagedDeviceAppAssignment" },
    @{ Name = "Security Baselines"; Function = "Get-IntuneDeviceManagementSecurityBaselineAssignment" },
    @{ Name = "Device Compliance Policies"; Function = "Get-IntuneDeviceCompliancePolicyAssignment" },
    @{ Name = "Device Configurations"; Function = "Get-IntuneDeviceConfigurationAssignment" },
    @{ Name = "Device Management Configuration Policies"; Function = "Get-IntuneDeviceManagementConfigurationPolicyAssignment" },
    @{ Name = "Administrative Templates"; Function = "Get-IntuneDeviceConfigurationAdministrativeTemplatesAssignment" },
    @{ Name = "Remediation Scripts"; Function = "Get-IntuneRemediationScriptAssignment" },
    @{ Name = "Autopilot Profiles"; Function = "Get-IntuneAutopilotProfileAssignment" },
    @{ Name = "Device Management Scripts"; Function = "Get-IntuneDeviceManagementScriptAssignment" },
    @{ Name = "Windows Information Protection Policies"; Function = "Get-IntuneWindowsInformationProtectionPolicyAssignment" },
    @{ Name = "Device Enrollment Configurations"; Function = "Get-IntuneDeviceEnrollmentConfigurationAssignment" },
    @{ Name = "Windows Update Policies"; Function = "Get-IntuneWindowsUpdateAssignment" },
    @{ Name = "Role Assignments"; Function = "Get-IntuneRoleAssignment" },
    @{ Name = "Cloud PC Role Assignments"; Function = "Get-CloudPcRoleAssignment" },
    @{ Name = "Terms and Conditions"; Function = "Get-IntuneTermsAndConditionsAssignment" },
    @{ Name = "Compliance Policies (Settings Catalog)"; Function = "Get-IntuneNewCompliancePolicyAssignment" },
    @{ Name = "Cloud PC Provisioning Policies"; Function = "Get-IntuneCloudPcProvisioningPolicyAssignment" },
    @{ Name = "WDAC Supplemental Policies"; Function = "Get-IntuneWdacSupplementalPolicyAssignment" },
    @{ Name = "macOS Shell Scripts"; Function = "Get-IntuneMacOsShellScriptAssignment" },
    @{ Name = "macOS Custom Attribute Scripts"; Function = "Get-IntuneMacOsCustomAttributeScriptAssignment" },
    @{ Name = "Intune Branding Profiles"; Function = "Get-IntuneBrandingProfileAssignment" },
    @{ Name = "App Configuration Policies (Managed Devices)"; Function = "Get-IntuneMobileAppConfigurationAssignment" },
    @{ Name = "iOS LoB App Provisioning Configurations"; Function = "Get-IntuneIosLobAppProvisioningConfigurationAssignment" }
)

foreach ($step in $processSteps) {
    Write-Host "Processing $($step.Name)..." -ForegroundColor Cyan
    try {
        $stepResults = & $step.Function -groupId $groupId
        $results += $stepResults
    } catch {
        Write-Warning "Failed to process $($step.Name): $_"
    }
}

# Output results
$finalResults = @($results)
if ($finalResults.Count -gt 0) {
    # Prepare the data for display and export
    $outputData = $finalResults | Select-Object DisplayName, ProfileType, 
        @{Name='IncludedGroups';Expression={$_.IncludedGroups -join '; '}},
        @{Name='ExcludedGroups';Expression={$_.ExcludedGroups -join '; '}}
    
    # Display results in console with all columns visible
    Write-Host "`nPolicy Assignments:" -ForegroundColor Green
    #$outputData | Format-Table -Wrap -AutoSize | Out-Host

    Write-Host "`nFound $($finalResults.Count) policies with assignments" -ForegroundColor Green
    Write-Host "If not all columns are visible, use -OutputFile to export to CSV" -ForegroundColor Yellow

    # Export to CSV if OutputFile is specified
    if ($OutputFile) {
        try {
            # Ensure the directory exists
            $directory = Split-Path -Path $OutputFile -Parent
            if (-not (Test-Path -Path $directory)) {
                New-Item -ItemType Directory -Path $directory -Force | Out-Null
            }
            
            $outputData | Export-Csv -Path $OutputFile -NoTypeInformation -Force
            Write-Host "Results exported to $OutputFile" -ForegroundColor Green
        } catch {
            Write-Error "Failed to export results to CSV: $_"
        }
    }
    
    # Return the raw data so it can be used with Out-GridView
    return $outputData
} else {
    Write-Host "No policies with assignments found" -ForegroundColor Yellow
}