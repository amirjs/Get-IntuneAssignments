#Requires -Version 7.1

<#PSScriptInfo

.VERSION 1.0.8

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
Initial release - Get all Intune Configuration Profile assignments

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
- Shows included and excluded groups for each assignment
- Displays filter information if configured
- Export results to CSV
- Filter by specific Azure AD group

.PARAMETER OutputFile
    Path to export the results as CSV. If not specified, results will be displayed in console.

.PARAMETER GroupName
    Name of the Azure AD group to filter assignments. Only assignments that include or exclude this group will be returned.

.EXAMPLE
    Get-IntuneAssignments
    Returns all Intune configuration assignments and displays them in the console.

.EXAMPLE
    Get-IntuneAssignments -OutputFile "C:\temp\assignments.csv"
    Retrieves all assignments and exports them to the specified CSV file.

.EXAMPLE
    Get-IntuneAssignments -GroupName "Pilot Users"
    Returns assignments that include or exclude the specified group.

.NOTES
    Version:        1.0.8
    Author:         Amir Joseph Sayes
    Company:        amirsayes.co.uk
    Creation Date:  2025-04-30
    Requirements:   
    - PowerShell 7.1 or higher
    - Microsoft Graph PowerShell SDK modules
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile,
    
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName
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
#endregion

#region Module Installation

# Module version configuration
$script:GraphModuleVersion = "2.25.0"

$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Beta.DeviceManagement",
    "Microsoft.Graph.Beta.Groups",
    "Microsoft.Graph.Beta.Devices.CorporateManagement",
    "Microsoft.Graph.Beta.DeviceManagement.Enrollment"
)

Write-Host "Checking required modules (version $script:GraphModuleVersion)..." -ForegroundColor Cyan
$modulesNeedingInstall = @()

foreach ($module in $requiredModules) {
    try {
        $existingModule = Get-Module -Name $module -ListAvailable | Where-Object { $_.Version -eq $script:GraphModuleVersion }
        if (-not $existingModule) {
            $modulesNeedingInstall += $module
        }
    } catch {
        Write-Warning "Error checking module $module`: $_"
    }
}

if ($modulesNeedingInstall.Count -gt 0) {
    Write-Host "The following modules need to be installed (version $script:GraphModuleVersion): $($modulesNeedingInstall -join ', ')" -ForegroundColor Yellow
    $userConsent = Read-Host "Do you want to proceed with installing the required modules? (Y/N)"
    if ($userConsent -match '^[Yy]$') {
        Write-Host "Installing required modules..." -ForegroundColor Cyan
        foreach ($module in $modulesNeedingInstall) {
            try {
                Write-Host "Installing $module version $script:GraphModuleVersion..." -ForegroundColor Yellow
                Install-Module -Name $module -RequiredVersion $script:GraphModuleVersion -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
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

# Import all required modules with specific version
foreach ($module in $requiredModules) {
    try {
        Import-Module -Name $module -RequiredVersion $script:GraphModuleVersion -Force -ErrorAction Stop
        Write-Verbose "Successfully imported $module version $script:GraphModuleVersion"
    } catch {
        Write-Error "Failed to import module $module. Error: $_"
        return
    }
}
#endregion

# Connect to Microsoft Graph if not already connected
try {
    if (-not (Get-MgContext)) {
        Write-Verbose "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes @(
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementApps.Read.All",
            "DeviceManagementManagedDevices.Read.All",
            "DeviceManagementServiceConfig.Read.All",
            "Group.Read.All",
            "Directory.Read.All"
        )
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
        $group = Get-MgBetaGroup -Filter "DisplayName eq '$GroupName'"
        if (-not $group) {
            Write-Error "Group '$GroupName' not found."
            return
        }
        $groupId = $group.Id
        Write-Host "Processing assignments for group: $GroupName" -ForegroundColor Green
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
    @{ Name = "Windows Information Protection Policies"; Function = "Get-IntuneWindowsInformationProtectionPolicyAssignment" }
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
    # Always display results in console with all columns visible
    Write-Host "`nPolicy Assignments:" -ForegroundColor Green
    $finalResults | Format-Table -Property DisplayName, ProfileType, 
        @{Name='IncludedGroups';Expression={$_.IncludedGroups -join '; '}},
        @{Name='ExcludedGroups';Expression={$_.ExcludedGroups -join '; '}} -Wrap -AutoSize 

    Write-Host "`nFound $($finalResults.Count) policies with assignments" -ForegroundColor Green
    write-host "If not all columns are visible, use -OutputFile to export to CSV" -ForegroundColor Yellow

    # Export to CSV if OutputFile is specified
    if ($OutputFile) {
        try {
            # Ensure the directory exists
            $directory = Split-Path -Path $OutputFile -Parent
            if (-not (Test-Path -Path $directory)) {
                New-Item -ItemType Directory -Path $directory -Force | Out-Null
            }
            
            $finalResults | Select-Object DisplayName, ProfileType, 
                @{Name='IncludedGroups';Expression={$_.IncludedGroups -join '; '}},
                @{Name='ExcludedGroups';Expression={$_.ExcludedGroups -join '; '}} |
            Export-Csv -Path $OutputFile -NoTypeInformation -Force
            Write-Host "Results exported to $OutputFile" -ForegroundColor Green
        } catch {
            Write-Error "Failed to export results to CSV: $_"
        }
    }
} else {
    Write-Host "No policies with assignments found" -ForegroundColor Yellow
}