# Get-IntuneAssignments

PowerShell script to retrieve all Intune Configuration Profile assignments, including Device Configuration, Compliance Policies, Security Baselines, Device Enrollment Configurations, and more.

## Version 1.0.12 - November 2025

**New Features:**
- ✨ Added support for Device Enrollment Configurations Assignments
- ✨ Added support for Intune Role Assignments and Cloud PC Role Assignments
- ✨ Fixed Out-GridView compatibility - script now returns PowerShell objects instead of formatting objects
- ✨ Results can now be properly used with `Out-GridView`, `Export-Csv`, and other PowerShell cmdlets
- ✨ Improved output handling for better console display

## Installation

```powershell
Install-Script -Name Get-IntuneAssignments
```

## Requirements

- PowerShell 7 or higher
- Microsoft Graph PowerShell SDK modules (will be automatically installed if missing):
    - DeviceManagementConfiguration.Read.All
    - DeviceManagementApps.Read.All
    - DeviceManagementManagedDevices.Read.All
    - DeviceManagementServiceConfig.Read.All
    - DeviceManagementScripts.Read.All
    - Group.Read.All
    - Directory.Read.All
    - CloudPC.Read.All (for Cloud PC Role Assignments)

## API Permissions

The following Microsoft Graph API permissions are required:

- DeviceManagementConfiguration.Read.All
- DeviceManagementApps.Read.All
- DeviceManagementManagedDevices.Read.All
- DeviceManagementServiceConfig.Read.All
- DeviceManagementScripts.Read.All
- Group.Read.All
- Directory.Read.All
- CloudPC.Read.All

These permissions will be requested automatically when connecting to Microsoft Graph.

## Usage

```powershell
# Get all assignments (interactive authentication)
Get-IntuneAssignments

# Export assignments to CSV (interactive authentication)
Get-IntuneAssignments -OutputFile "C:\temp\assignments.csv"

# Get assignments for a specific group (interactive authentication)
Get-IntuneAssignments -GroupName "Pilot Users"

# Use with Out-GridView for interactive filtering and sorting (NEW in v1.0.12)
$assignments = Get-IntuneAssignments
$assignments | Out-GridView

# Filter and view specific policy types (NEW in v1.0.12)
$assignments = Get-IntuneAssignments
$assignments | Where-Object { $_.ProfileType -like "*enrollment*" } | Out-GridView -Title "Enrollment Configurations"

# Export filtered results
$assignments = Get-IntuneAssignments
$assignments | Where-Object { $_.ProfileType -eq "Mobile App Deployment" } | Export-Csv "C:\temp\apps.csv" -NoTypeInformation

# Connect interactively to a specific tenant
Get-IntuneAssignments -AuthMethod Interactive -TenantId "contoso.onmicrosoft.com"

# Certificate authentication (thumbprint, app registration with certificate in store)
Get-IntuneAssignments -AuthMethod Certificate -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678"

# Client secret authentication
$credential = New-Object System.Management.Automation.PSCredential("12345678-1234-1234-1234-123456789012", (ConvertTo-SecureString "YourClientSecret" -AsPlainText -Force))
Get-IntuneAssignments -AuthMethod ClientSecret -TenantId "contoso.onmicrosoft.com" -ClientSecretCredential $credential

# User-assigned managed identity authentication
Get-IntuneAssignments -AuthMethod UserManagedIdentity -TenantId "contoso.onmicrosoft.com" -ClientId "<user-assigned-managed-identity-client-id>"

# System-assigned managed identity authentication
Get-IntuneAssignments -AuthMethod SystemManagedIdentity -TenantId "contoso.onmicrosoft.com"

# Group filtering and CSV export with certificate authentication
Get-IntuneAssignments -AuthMethod Certificate -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678" -GroupName "Pilot Users" -OutputFile "C:\temp\PilotUsersAssignments.csv"
```

## Features

- Retrieves assignments for:
  - Device Configuration Profiles
  - Device Management Configuration Policies
  - Compliance Policies
  - Security Baselines
  - Administrative Templates
  - App Protection Policies
  - Managed Device App Deployments (Win32, LOB, Store, etc)
  - Windows Information Protection Policies
  - Remediation Scripts
  - Device Management Scripts
  - Autopilot Profiles (v1)
  - Device Enrollment Configurations 
    - Device Enrollment Limit Configurations
    - Device Enrollment Platform Restrictions
    - Windows Hello for Business Configurations
    - Enrollment Status Page (ESP) Configurations
    - Windows Autopilot Enrollment Status Page
    - Co-management Authority Configurations
  - Windows Update Policies
    - Windows Quality Update Profiles
    - Windows Feature Update Profiles
    - Windows Update Rings
    - Windows Driver Update Profiles
  - Intune Role Assignments
    - Shows administrative role assignments and their resource scopes
    - Displays both group and user assignments
  -Cloud PC Role Assignments
    - Windows 365 Cloud PC administrative role assignments
    - Includes role definition names and directory scopes
- Shows included and excluded groups for each assignment
- Displays filter information if configured
- Export results to CSV
- Filter by specific Azure AD group
- **Returns PowerShell objects** - compatible with `Out-GridView`, `Export-Csv`, and other cmdlets

## Output Format

The script returns PowerShell objects (not formatting objects) with the following properties:
- **DisplayName**: Name of the policy/profile
- **ProfileType**: Type of configuration (e.g., Device Configuration, Compliance Policy, deviceEnrollmentLimitConfiguration)
- **IncludedGroups**: Groups included in the assignment (with filter information if applicable)
- **ExcludedGroups**: Groups excluded from the assignment

**New in v1.0.12:** The script now returns actual PowerShell custom objects instead of formatting objects, making it compatible with:
- `Out-GridView` - Interactive grid view with sorting and filtering
- `Export-Csv` - Export to CSV files
- `Where-Object` - Filter results in the pipeline
- `Select-Object` - Select specific properties
- Any other PowerShell cmdlet that works with objects


## Authentication Methods

Supported authentication methods:

- **Interactive** (default): Prompts for user login interactively.
- **Certificate**: Uses a certificate in the local certificate store, specified by thumbprint. Only the `-CertificateThumbprint` parameter is supported. `-CertificatePath` is not supported.
- **ClientSecret**: Uses a client secret via a PSCredential object.
- **UserManagedIdentity**: Uses a user-assigned managed identity.
- **SystemManagedIdentity**: Uses a system-assigned managed identity.

**Note:** For certificate authentication, the certificate must be installed in the local certificate store and accessible by thumbprint. The script does not support loading certificates from file paths.

## Contributing

Contributions are welcome! Please submit a pull request.

## Changelog

### Version 1.0.12 - November 2025
- ✨ Added support for Intune Role Assignments
  - Shows administrative role assignments and their resource scopes
  - Displays both group and user assignments
- ✨ Added support for Cloud PC Role Assignments
  - Windows 365 Cloud PC administrative role assignments
  - Includes role definition names and directory scopes
- ✨ Added support for Device Enrollment Configurations
  - Device Enrollment Limit Configurations
  - Device Enrollment Platform Restrictions
  - Windows Hello for Business Configurations
  - Enrollment Status Page (ESP) Configurations
  - Windows Autopilot Enrollment Status Page
  - Co-management Authority Configurations
- ✨ Added CloudPC.Read.All permission to Graph scopes
- ✨ Fixed Out-GridView compatibility - script now returns PowerShell objects instead of formatting objects
- ✨ Results can now be used with `Out-GridView`, `Export-Csv`, and other PowerShell cmdlets

### Version 1.0.11 - 2025
- ✨ Added support for Windows Update Policies:
  - Windows Quality Update Profiles
  - Windows Feature Update Profiles
  - Windows Update Rings
  - Windows Driver Update Profiles

### Version 1.0.10 - 2025
- ✨ Added certificate-based authentication (thumbprint)
- ✨ Added client secret authentication
- ✨ Added managed identity authentication (user-assigned and system-assigned)

### Version 1.0.9 - 2025
- 🐛 Fixed bug with group names containing spaces
- ✨ Added logic to handle multiple groups matching search criteria

### Version 1.0.7 - 2025
- ✨ Enhanced function capabilities

### Version 1.0.1 - Initial Release
- ✨ Get all Intune Configuration Profile assignments
- ✨ Support for Device Configuration, Compliance Policies, Security Baselines, Apps, and more

## License

[MIT License](./LICENSE)