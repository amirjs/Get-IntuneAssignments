#Requires -Version 7.1

<#PSScriptInfo

.VERSION 1.0.3

.GUID 3b9c9df5-3b5f-4c1a-9a6c-097be91fa292

.AUTHOR Amir Joseph Sayes

.COMPANYNAME amirsayes.co.uk

.COPYRIGHT (c) 2025. All rights reserved.

.TAGS Intune Configuration Management Microsoft Graph Azure

.LICENSEURI https://github.com/YOURUSERNAME/Get-IntuneAssignments/blob/main/LICENSE

.PROJECTURI https://github.com/YOURUSERNAME/Get-IntuneAssignments

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
    - Compliance Policies
    - Security Baselines
    - Administrative Templates
    - App Protection Policies
    - App Configuration Policies
    - Windows Information Protection Policies
    - Remediation Scripts
    - Device Management Scripts
    - Autopilot Profiles

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
    Version:        1.0.3
    Author:         Amir Joseph Sayes
    Company:        amirsayes.co.uk
    Creation Date:  2025-04-30
    Requirements:   
    - PowerShell 5.1 or higher
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

function Get-IntuneManagedDeviceAppConfigurationAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $AppConfiguration = Get-MgBetaDeviceAppManagementMobileAppConfiguration -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $AppConfiguration = Get-MgBetaDeviceAppManagementMobileAppConfiguration -All -ExpandProperty "assignments"
    }

    foreach ($config in $AppConfiguration) {
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
                ProfileType = "Managed Device App Configuration"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
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
    @{ Name = "Managed Device App Configurations"; Function = "Get-IntuneManagedDeviceAppConfigurationAssignment" },
    @{ Name = "Security Baselines"; Function = "Get-IntuneDeviceManagementSecurityBaselineAssignment" },
    @{ Name = "Device Compliance Policies"; Function = "Get-IntuneDeviceCompliancePolicyAssignment" },
    @{ Name = "Device Configurations"; Function = "Get-IntuneDeviceConfigurationAssignment" },
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