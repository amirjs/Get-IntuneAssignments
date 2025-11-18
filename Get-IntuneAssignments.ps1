#Requires -Version 7

<#PSScriptInfo

.VERSION 1.0.15

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
Microsoft.Graph.Beta.DeviceManagement
Microsoft.Graph.Beta.Groups
Microsoft.Graph.Beta.Devices.CorporateManagement
Microsoft.Graph.Beta.DeviceManagement.Enrollment

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES

v1.0.15 - November 2025:
        - Added delimiter parameter for export-csv
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
    
    Required Microsoft Graph API permissions:
    - DeviceManagementConfiguration.Read.All
    - DeviceManagementApps.Read.All
    - DeviceManagementManagedDevices.Read.All
    - DeviceManagementServiceConfig.Read.All
    - Group.Read.All
    - DeviceManagementRBAC.Read.All (for Intune Role Assignments)
    - CloudPC.Read.All (for Cloud PC Role Assignments)

    - Shows included and excluded groups for each assignment
    - Displays filter information if configured
    - Export results to CSV
    - Filter by specific Azure AD group

.PARAMETER OutputFile
    Path to export the results as CSV. If not specified, results will be displayed in console.

.PARAMETER CsvDelimiter
    Set delimiter to separate values in the output file. Default is a comma (,), but can be set to colon (:), semicolon (;) or pipe (|).

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

.NOTES
    Version:        1.0.15
    Author:         Amir Joseph Sayes
    Company:        amirsayes.co.uk
    Creation Date:  2025-04-30
    Last Updated:   2025-11-09
    Requirements:   
    - PowerShell 7 or higher
    - Microsoft Graph PowerShell SDK modules (automatically installed if missing)
    
    For the latest version and updates, visit:
    https://github.com/amirjs/Get-IntuneAssignments

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

#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile,

    [Parameter(Mandatory = $false)]
    [ValidateSet(',', ':', ';', '|')]
    [string]$CsvDelimiter = ',',
    
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

function Get-IntuneAppProtectionAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $AppProtectionPolicy = Get-MgBetaDeviceAppManagementManagedAppPolicy -Filter "displayName eq '$displayName'"
    } else {
        $AppProtectionPolicy = Get-MgBetaDeviceAppManagementManagedAppPolicy -All
    }

    foreach ($policy in $AppProtectionPolicy) {        
        $assignments = $null
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        if ($policy.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.androidManagedAppProtection") {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.Id)')/assignments"
        } elseif ($policy.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.iosManagedAppProtection") {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.Id)')/assignments"
        } elseif ($policy.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.windowsInformationProtectionAppLockerFileProtection") {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionAppLockerFileProtections('$($policy.Id)')/assignments"
        } elseif ($policy.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.windowsManagedAppProtections") {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.Id)')/assignments"
        } elseif ($policy.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.targetedManagedAppConfiguration") {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations('$($policy.Id)')/assignments"            
        } else {
            Write-Output "No App Protection Policy assignment found for $($policy.displayName)"
            continue
        }

        $assignments = Invoke-MgGraphRequest -Uri $uri -Headers @{ConsistencyLevel = "eventual"} -ContentType "application/json"

        foreach ($assignment in $assignments.value) {
            # Skip if we're looking for a specific group and this isn't it
            if ($groupId -and $assignment.target.groupId -ne $groupId) {
                continue
            }

            if ($assignment.target.'@odata.type' -eq "#microsoft.graph.groupAssignmentTarget") {
                $CurrentincludedGroup = (Get-MgBetaGroup -GroupId $($assignment.target.groupId)).DisplayName
                if ($($assignment.target.deviceAndAppManagementAssignmentFilterId) -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.target.deviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.target.'@odata.type' -eq "#microsoft.graph.exclusionGroupAssignmentTarget") {
                $excludedGroups += (Get-MgBetaGroup -GroupId $($assignment.target.groupId)).DisplayName
            } elseif ($assignment.target.'@odata.type' -eq "#microsoft.graph.allDevicesAssignmentTarget") {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.target.deviceAndAppManagementAssignmentFilterId) -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.target.deviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.target.'@odata.type' -eq "#microsoft.graph.allLicensedUsersAssignmentTarget") {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.target.deviceAndAppManagementAssignmentFilterId) -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.target.deviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            }
        }

        # Only return results if we found assignments (and they match our group filter if specified)
        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $policy.DisplayName
                ProfileType = $policy.AdditionalProperties.'@odata.type' -replace '^#microsoft\.graph\.', ''
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

    # Get Mobile Apps instead of App Configurations
    if ($displayName) {
        $MobileApps = Get-MgBetaDeviceAppManagementMobileApp -Filter "displayName eq '$displayName'" -ErrorAction SilentlyContinue
    } else {
        $MobileApps = Get-MgBetaDeviceAppManagementMobileApp -All -ErrorAction SilentlyContinue
    }

    if ($null -eq $MobileApps) {
        # No mobile apps found matching the criteria, return nothing for this function call
        return
    }

    # Process each app
    foreach ($app in $MobileApps) {
        # Get assignments for this specific app using Invoke-MgGraphRequest
        # App assignments are under /deviceAppManagement/mobileApps/{appId}/assignments
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$($app.Id)')/assignments"
        try {
            # Added -Headers for eventual consistency, similar to App Protection Policy function
            $assignmentsResult = Invoke-MgGraphRequest -Uri $uri -Method Get -Headers @{ConsistencyLevel = "eventual"} -ErrorAction Stop
            $assignments = $assignmentsResult.value
        } catch {
            # Silently continue if assignments fail to load for an app
            # Write-Warning "Failed to get assignments for app '$($app.DisplayName)' ($($app.Id)): $_"
            continue
        }

        if ($null -eq $assignments -or $assignments.Count -eq 0) {
            # No assignments found for this app
            continue
        }

        $includedGroups = @()
        # Excluded groups are not directly part of the assignment target in the same way for apps.
        # We will only report included groups/targets.
        $hasMatchingAssignment = $false # Flag to track if any assignment matches the group filter

        foreach ($assignment in $assignments) {
            $CurrentFilterName = $null
            $CurrentIncludedGroup = $null
            $isMatch = $false # Flag for this specific assignment

            # Determine target type and check group filter if applicable
            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                # Check if filtering by group ID
                if ($groupId) {
                    # Only proceed if this assignment targets the specified group ID
                    if ($assignment.target.groupId -eq $groupId) {
                        # Attempt to get group display name
                        $groupInfo = Get-MgBetaGroup -GroupId $assignment.target.groupId -ErrorAction SilentlyContinue
                        $CurrentIncludedGroup = if ($groupInfo) { $groupInfo.DisplayName } else { "Group ID: $($assignment.target.groupId) (Not Found/No Access)" }
                        $isMatch = $true
                    } else {
                        continue # Skip assignment if group ID doesn't match filter
                    }
                } else {
                    # Not filtering by group ID, process this assignment
                    $groupInfo = Get-MgBetaGroup -GroupId $assignment.target.groupId -ErrorAction SilentlyContinue
                    $CurrentIncludedGroup = if ($groupInfo) { $groupInfo.DisplayName } else { "Group ID: $($assignment.target.groupId) (Not Found/No Access)" }
                    $isMatch = $true
                }

                # Get filter name if applicable and group was determined
                if ($isMatch) {
                     if ($assignment.target.deviceAndAppManagementAssignmentFilterId -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                        $filterInfo = Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -ErrorAction SilentlyContinue
                        $CurrentFilterName = if ($filterInfo) { " | Filter: $($filterInfo.DisplayName)" } else { " | Filter ID: $($assignment.target.deviceAndAppManagementAssignmentFilterId) (Not Found/No Access)" }
                    } else {
                        $CurrentFilterName = " | No Filter"
                    }
                }

            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                # Only include "All Devices" if not filtering by a specific group
                if (-not $groupId) {
                    $CurrentIncludedGroup = "All Devices"
                    $isMatch = $true
                    if ($assignment.target.deviceAndAppManagementAssignmentFilterId -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                         $filterInfo = Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -ErrorAction SilentlyContinue
                         $CurrentFilterName = if ($filterInfo) { " | Filter: $($filterInfo.DisplayName)" } else { " | Filter ID: $($assignment.target.deviceAndAppManagementAssignmentFilterId) (Not Found/No Access)" }
                    } else {
                        $CurrentFilterName = " | No Filter"
                    }
                } else {
                    continue # Skip if filtering by group
                }
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                 # Only include "All Users" if not filtering by a specific group
                if (-not $groupId) {
                    $CurrentIncludedGroup = "All Users"
                    $isMatch = $true
                     if ($assignment.target.deviceAndAppManagementAssignmentFilterId -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                         $filterInfo = Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -ErrorAction SilentlyContinue
                         $CurrentFilterName = if ($filterInfo) { " | Filter: $($filterInfo.DisplayName)" } else { " | Filter ID: $($assignment.target.deviceAndAppManagementAssignmentFilterId) (Not Found/No Access)" }
                    } else {
                        $CurrentFilterName = " | No Filter"
                    }
                } else {
                    continue # Skip if filtering by group
                }
            }

            # If we identified an included group/target and it matches filters (if any), add it
            if ($isMatch -and $CurrentIncludedGroup) {
                 $includedGroups += $CurrentIncludedGroup + $CurrentFilterName
                 $hasMatchingAssignment = $true # Mark that we found at least one relevant assignment for this app
            }
        } # End foreach assignment

        # Only return results for this app if we found assignments that matched the criteria (especially the group filter if specified)
        if ($hasMatchingAssignment) {
            [PSCustomObject]@{
                DisplayName = $app.DisplayName
                # Update ProfileType to reflect that this function now gets App Deployments
                ProfileType = "Mobile App Deployment"
                IncludedGroups = $includedGroups
                # ExcludedGroups property is set to null as it doesn't map directly for app assignments in this context
                ExcludedGroups = $null
            }
        }
    } # End foreach app
}

function Get-IntuneDeviceManagementSecurityBaselineAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $SecurityBaseline = Get-MgBetaDeviceManagementIntent -Filter "displayName eq '$displayName'" -ExpandProperty assignments
    } else {
        $SecurityBaseline = Get-MgBetaDeviceManagementIntent -All -ExpandProperty assignments
    }

    foreach ($baseline in $SecurityBaseline) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $baseline.Assignments
        foreach ($assignment in $assignments) {
            # Skip if we're looking for a specific group and this isn't it
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        # Only return results if we found assignments (and they match our group filter if specified)
        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $baseline.DisplayName
                TemplateName = (Get-MgBetaDeviceManagementTemplate -DeviceManagementTemplateId $baseline.TemplateId).DisplayName
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

    if ($displayName) {
        $CompliancePolicy = Get-MgBetaDeviceManagementDeviceCompliancePolicy -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $CompliancePolicy = Get-MgBetaDeviceManagementDeviceCompliancePolicy -All -ExpandProperty "assignments"
    }

    foreach ($policy in $CompliancePolicy) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $policy.Assignments
        foreach ($assignment in $assignments) {
            # Skip if we're looking for a specific group and this isn't it
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        # Only return results if we found assignments (and they match our group filter if specified)
        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $policy.DisplayName
                ProfileType = $policy.AdditionalProperties.'@odata.type' -replace '^#microsoft\.graph\.', ''
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

    if ($displayName) {
        $DeviceConfiguration = Get-MgBetaDeviceManagementDeviceConfiguration -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $DeviceConfiguration = Get-MgBetaDeviceManagementDeviceConfiguration -All -ExpandProperty "assignments"
    }

    foreach ($config in $DeviceConfiguration) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $config.Assignments
        foreach ($assignment in $assignments) {
            # Skip if we're looking for a specific group and this isn't it
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        # Only return results if we found assignments (and they match our group filter if specified)
        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $config.DisplayName
                ProfileType = $config.AdditionalProperties.'@odata.type' -replace '^#microsoft\.graph\.', ''
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

    if ($displayName) {
        $ConfigurationPolicy = Get-MgBetaDeviceManagementConfigurationPolicy -Filter "name eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $ConfigurationPolicy = Get-MgBetaDeviceManagementConfigurationPolicy -All -ExpandProperty "assignments"
    }

    foreach ($policy in $ConfigurationPolicy) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $policy.Assignments
        foreach ($assignment in $assignments) {
            # Skip if we're looking for a specific group and this isn't it
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        # Only return results if we found assignments (and they match our group filter if specified)
        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $policy.Name
                ProfileType = "Device Management Configuration Policy"
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

    if ($displayName) {
        $AdministrativeTemplate = Get-MgBetaDeviceManagementGroupPolicyConfiguration -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $AdministrativeTemplate = Get-MgBetaDeviceManagementGroupPolicyConfiguration -All -ExpandProperty "assignments"
    }

    foreach ($template in $AdministrativeTemplate) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $template.Assignments
        foreach ($assignment in $assignments) {
            # Skip if we're looking for a specific group and this isn't it
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        # Only return results if we found assignments (and they match our group filter if specified)
        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $template.DisplayName
                ProfileType = "AdministrativeTemplates"
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

    if ($displayName) {
        $RemediationScript = Get-MgBetaDeviceManagementDeviceHealthScript -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $RemediationScript = Get-MgBetaDeviceManagementDeviceHealthScript -All -ExpandProperty "assignments"
    }

    foreach ($script in $RemediationScript) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $script.Assignments
        foreach ($assignment in $assignments) {
            # Skip if we're looking for a specific group and this isn't it
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        # Only return results if we found assignments (and they match our group filter if specified)
        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $script.DisplayName
                ProfileType = "Remediation Script"
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
    if ($displayName) {
        $QualityUpdateProfile = Get-MgBetaDeviceManagementWindowsQualityUpdateProfile -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $QualityUpdateProfile = Get-MgBetaDeviceManagementWindowsQualityUpdateProfile -All -ExpandProperty "assignments"
    }

    foreach ($profile in $QualityUpdateProfile) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $profile.Assignments
        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $profile.DisplayName
                ProfileType = "Windows Quality Update Profile"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }

    # Windows Feature Update Profiles
    if ($displayName) {
        $FeatureUpdateProfile = Get-MgBetaDeviceManagementWindowsFeatureUpdateProfile -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $FeatureUpdateProfile = Get-MgBetaDeviceManagementWindowsFeatureUpdateProfile -All -ExpandProperty "assignments"
    }

    foreach ($profile in $FeatureUpdateProfile) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $profile.Assignments
        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $profile.DisplayName
                ProfileType = "Windows Feature Update Profile"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }

    # Windows Update Ring Settings (direct Graph call)
    $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdatePolicies?`$expand=assignments"
    try {
        $UpdateRings = Invoke-MgGraphRequest -Uri $uri -Method Get -Headers @{ConsistencyLevel = "eventual"}
        
        foreach ($ring in $UpdateRings.value) {
            $includedGroups = @()
            $excludedGroups = @()
            $FilterName = @()

            foreach ($assignment in $ring.assignments) {
                if ($groupId -and $assignment.target.groupId -ne $groupId) {
                    continue
                }

                if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                    $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.target.groupId)).DisplayName
                    if ($($assignment.target.deviceAndAppManagementAssignmentFilterId) -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                        $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.target.deviceAndAppManagementAssignmentFilterId)).DisplayName
                    } else {
                        $FilterName = " | No Filter"
                    }
                    $includedGroups += $CurrentincludedGroup + $FilterName
                } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                    $CurrentincludedGroup = "All Devices"
                    if ($($assignment.target.deviceAndAppManagementAssignmentFilterId) -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                        $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.target.deviceAndAppManagementAssignmentFilterId)).DisplayName
                    } else {
                        $FilterName = " | No Filter"
                    }
                    $includedGroups += $CurrentincludedGroup + $FilterName
                } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                    $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.target.groupId)).DisplayName
                }
            }

            if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
                [PSCustomObject]@{
                    DisplayName = $ring.displayName
                    ProfileType = "Windows Update Ring"
                    IncludedGroups = $includedGroups
                    ExcludedGroups = $excludedGroups
                }
            }
        }
    } catch {
        Write-Warning "Failed to retrieve Windows Update Ring assignments: $_"
    }

    # Windows Driver Update Profiles (direct Graph call)
    $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles?`$expand=assignments"
    try {
        $DriverUpdateProfiles = Invoke-MgGraphRequest -Uri $uri -Method Get -Headers @{ConsistencyLevel = "eventual"}
        
        foreach ($profile in $DriverUpdateProfiles ) {
            $includedGroups = @()
            $excludedGroups = @()
            $FilterName = @()

            foreach ($assignment in $profile.assignments) {
                if ($groupId -and $assignment.target.groupId -ne $groupId) {
                    continue
                }

                if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                    $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.target.groupId)).DisplayName
                    if ($($assignment.target.deviceAndAppManagementAssignmentFilterId) -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                        $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.target.deviceAndAppManagementAssignmentFilterId)).DisplayName
                    } else {
                        $FilterName = " | No Filter"
                    }
                    $includedGroups += $CurrentincludedGroup + $FilterName
                } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                    $CurrentincludedGroup = "All Devices"
                    if ($($assignment.target.deviceAndAppManagementAssignmentFilterId) -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                        $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.target.deviceAndAppManagementAssignmentFilterId)).DisplayName
                    } else {
                        $FilterName = " | No Filter"
                    }
                    $includedGroups += $CurrentincludedGroup + $FilterName
                } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                    $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.target.groupId)).DisplayName
                }
            }

            if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
                [PSCustomObject]@{
                    DisplayName = $profile.displayName
                    ProfileType = "Windows Driver Update Profile"
                    IncludedGroups = $includedGroups
                    ExcludedGroups = $excludedGroups
                }
            }
        }
    } catch {
        Write-Warning "Failed to retrieve Windows Driver Update Profile assignments: $_"
    }
}

function Get-IntuneAutopilotProfileAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $AutopilotProfile = Get-MgBetaDeviceManagementWindowsAutopilotDeploymentProfile -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $AutopilotProfile = Get-MgBetaDeviceManagementWindowsAutopilotDeploymentProfile -All -ExpandProperty "assignments"
    }

    foreach ($profile in $AutopilotProfile) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $profile.Assignments
        foreach ($assignment in $assignments) {
            # Skip if we're looking for a specific group and this isn't it
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        # Only return results if we found assignments (and they match our group filter if specified)
        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $profile.DisplayName
                ProfileType = "Autopilot Profile"
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

    if ($displayName) {
        $DeviceManagementScript = Get-MgBetaDeviceManagementScript -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $DeviceManagementScript = Get-MgBetaDeviceManagementScript -All -ExpandProperty "assignments"
    }

    foreach ($script in $DeviceManagementScript) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $script.Assignments
        foreach ($assignment in $assignments) {
            # Skip if we're looking for a specific group and this isn't it
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        # Only return results if we found assignments (and they match our group filter if specified)
        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $script.DisplayName
                ProfileType = "Device Management Script"
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

    if ($displayName) {
        $WIPPolicy = Get-MgBetaDeviceAppManagementMdmWindowsInformationProtectionPolicy -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $WIPPolicy = Get-MgBetaDeviceAppManagementMdmWindowsInformationProtectionPolicy -All -ExpandProperty "assignments"
    }

    foreach ($policy in $WIPPolicy) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $policy.Assignments
        foreach ($assignment in $assignments) {
            # Skip if we're looking for a specific group and this isn't it
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        # Only return results if we found assignments (and they match our group filter if specified)
        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $policy.DisplayName
                ProfileType = "Windows Information Protection Policy"
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

    if ($displayName) {
        $EnrollmentConfigurations = Get-MgBetaDeviceManagementDeviceEnrollmentConfiguration -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $EnrollmentConfigurations = Get-MgBetaDeviceManagementDeviceEnrollmentConfiguration -All -ExpandProperty "assignments"
    }

    foreach ($config in $EnrollmentConfigurations) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $config.Assignments
        foreach ($assignment in $assignments) {
            # Skip if we're looking for a specific group and this isn't it
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        # Only return results if we found assignments (and they match our group filter if specified)
        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $config.DisplayName
                ProfileType = $config.AdditionalProperties.'@odata.type' -replace '^#microsoft\.graph\.', ''
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

    if ($displayName) {
        $RoleAssignments = Get-MgBetaDeviceManagementRoleAssignment -Filter "displayName eq '$displayName'"
    } else {
        $RoleAssignments = Get-MgBetaDeviceManagementRoleAssignment -All
    }

    foreach ($roleAssignment in $RoleAssignments) {
        $includedGroups = @()
        $hasMatchingAssignment = $false

        # Check if we're filtering by group and if this role assignment matches
        if ($groupId) {
            # Check if the group is in Members or ResourceScopes
            $isInMembers = $roleAssignment.Members -contains $groupId
            $isInScopes = $roleAssignment.ResourceScopes -contains $groupId
            
            if (-not ($isInMembers -or $isInScopes)) {
                continue  # Skip this role assignment if the group isn't involved
            }
            $hasMatchingAssignment = $true
        } else {
            $hasMatchingAssignment = $true
        }

        # Get member names (assigned to) - can be users or groups
        if ($roleAssignment.Members) {
            foreach ($memberId in $roleAssignment.Members) {
                try {
                    $memberGroup = Get-MgBetaGroup -GroupId $memberId -ErrorAction SilentlyContinue
                    if ($memberGroup) {
                        $memberName = "$($memberGroup.DisplayName) (Member)"
                    } else {
                        # Could be a user, try to get user info
                        $memberUser = Get-MgBetaUser -UserId $memberId -ErrorAction SilentlyContinue
                        if ($memberUser) {
                            $memberName = "$($memberUser.DisplayName) (User)"
                        } else {
                            $memberName = "$memberId (Member)"
                        }
                    }

                    # Get resource scope for this member
                    if ($roleAssignment.ResourceScopes) {
                        foreach ($scopeId in $roleAssignment.ResourceScopes) {
                            try {
                                $scopeGroup = Get-MgBetaGroup -GroupId $scopeId -ErrorAction SilentlyContinue
                                if ($scopeGroup) {
                                    $includedGroups += "$memberName | Scope: $($scopeGroup.DisplayName)"
                                } else {
                                    $includedGroups += "$memberName | Scope: $scopeId"
                                }
                            } catch {
                                $includedGroups += "$memberName | Scope: $scopeId"
                            }
                        }
                    } else {
                        $includedGroups += $memberName
                    }
                } catch {
                    $includedGroups += "$memberId (Member)"
                }
            }
        }

        # Only return results if we found members (and they match our group filter if specified)
        if ($hasMatchingAssignment -and $includedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $roleAssignment.DisplayName
                ProfileType = "Role Assignment"
                IncludedGroups = $includedGroups
                ExcludedGroups = @()  # Role assignments don't have exclusions
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
        if ($displayName) {
            # Cloud PC role assignments don't support filtering by displayName directly
            # We'll get all and filter in PowerShell
            $RoleAssignments = Get-MgBetaRoleManagementCloudPcRoleAssignment -All | Where-Object { $_.DisplayName -eq $displayName }
        } else {
            $RoleAssignments = Get-MgBetaRoleManagementCloudPcRoleAssignment -All
        }
    } catch {
        Write-Warning "Failed to retrieve Cloud PC role assignments. This might require additional permissions or the Cloud PC service may not be configured."
        return
    }

    foreach ($roleAssignment in $RoleAssignments) {
        $includedGroups = @()
        $hasMatchingAssignment = $false

        # Cloud PC role assignments use PrincipalIds (array) which contains the assigned user/group
        # Check if we're filtering by group and if this role assignment matches
        if ($groupId) {
            # Check if the group is in the principals or directory scopes
            $isInPrincipal = $roleAssignment.PrincipalIds -contains $groupId
            $isInScopes = $roleAssignment.DirectoryScopeIds -contains $groupId
            
            if (-not ($isInPrincipal -or $isInScopes)) {
                continue  # Skip this role assignment if the group isn't involved
            }
            $hasMatchingAssignment = $true
        } else {
            $hasMatchingAssignment = $true
        }

        # Get role definition name for better context
        $roleName = "Cloud PC Role"
        if ($roleAssignment.RoleDefinitionId) {
            try {
                $roleDefinition = Get-MgBetaRoleManagementCloudPcRoleDefinition -UnifiedRoleDefinitionId $roleAssignment.RoleDefinitionId -ErrorAction SilentlyContinue
                if ($roleDefinition) {
                    $roleName = $roleDefinition.DisplayName
                }
            } catch {
                # If we can't get the role definition, use the ID
                $roleName = "Cloud PC Role ($($roleAssignment.RoleDefinitionId))"
            }
        }

        # Get principal names (assigned to) - can be users or groups
        if ($roleAssignment.PrincipalIds) {
            foreach ($principalId in $roleAssignment.PrincipalIds) {
                try {
                    $principalGroup = Get-MgBetaGroup -GroupId $principalId -ErrorAction SilentlyContinue
                    if ($principalGroup) {
                        $principalName = "$($principalGroup.DisplayName) (Member)"
                    } else {
                        # Could be a user, try to get user info
                        $principalUser = Get-MgBetaUser -UserId $principalId -ErrorAction SilentlyContinue
                        if ($principalUser) {
                            $principalName = "$($principalUser.DisplayName) (User)"
                        } else {
                            $principalName = "$principalId (Member)"
                        }
                    }

                    # Get directory scope names for this principal
                    if ($roleAssignment.DirectoryScopeIds) {
                        foreach ($scopeId in $roleAssignment.DirectoryScopeIds) {
                            try {
                                $scopeGroup = Get-MgBetaGroup -GroupId $scopeId -ErrorAction SilentlyContinue
                                if ($scopeGroup) {
                                    $includedGroups += "$principalName | Role: $roleName | Scope: $($scopeGroup.DisplayName)"
                                } else {
                                    $includedGroups += "$principalName | Role: $roleName | Scope: $scopeId"
                                }
                            } catch {
                                $includedGroups += "$principalName | Role: $roleName | Scope: $scopeId"
                            }
                        }
                    } else {
                        $includedGroups += "$principalName | Role: $roleName"
                    }
                } catch {
                    $includedGroups += "$principalId (Member) | Role: $roleName"
                }
            }
        }

        # Only return results if we found principals (and they match our group filter if specified)
        if ($hasMatchingAssignment -and $includedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = if ($roleAssignment.DisplayName) { $roleAssignment.DisplayName } else { "Cloud PC Role Assignment" }
                ProfileType = "Cloud PC Role Assignment"
                IncludedGroups = $includedGroups
                ExcludedGroups = @()  # Role assignments don't have exclusions
            }
        }
    }
}
#endregion

#region Module Installation

$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Beta.DeviceManagement",
    "Microsoft.Graph.Beta.Groups",
    "Microsoft.Graph.Beta.Devices.CorporateManagement",
    "Microsoft.Graph.Beta.DeviceManagement.Enrollment",
    "Microsoft.Graph.Beta.DeviceManagement.Administration"       
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
        $group = Get-MgBetaGroup -Search "displayName:$GroupName" -CountVariable c -ConsistencyLevel eventual -All     
        if (-not $group) {
            Write-Error "Group '$GroupName' not found."
            return
        }
        # if more than one $group is found, prompt user to select one from a list of numbers and then assigne the actual object to $groupId
        if ($c -gt 1) {
            Write-Host "Multiple groups found. Please select one:" -ForegroundColor Yellow
            $group | ForEach-Object { Write-Host "$($_.Id): $($_.DisplayName)" -ForegroundColor Cyan }
            $selectedGroupId = Read-Host "Enter the ID of the group you want to use"
            $groupId= ($group | Where-Object { $_.Id -eq $selectedGroupId }).Id
            $groupDisplayName= ($group | Where-Object { $_.Id -eq $selectedGroupId }).DisplayName
            if (-not $groupId) {
                Write-Error "Invalid group ID selected."
                return
            }
        } else {
            $groupId = $group.Id
            $groupDisplayName = $group.DisplayName
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
    @{ Name = "Cloud PC Role Assignments"; Function = "Get-CloudPcRoleAssignment" }
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
            
            $outputData | Export-Csv -Path $OutputFile -Delimiter $CsvDelimiter -NoTypeInformation -Force
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