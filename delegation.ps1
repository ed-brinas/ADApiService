<# 
Delegation: Parent LAB\svc_adapi manages OU in child NEW

Grants:
 - Create/Delete User objects
 - Reset Password (extended right) on users
 - Write all properties on users
 - Modify group membership (write 'member' on groups)
#>

# ------------------ CONFIG ------------------
$TargetOUDN    = "OU=_AdminAccounts,DC=NEW,DC=LAB,DC=LOCAL"   # Full DN in CHILD
$SvcUPN        = "svc_ad-adm-portal@lab.local"                # Service account in PARENT
$ChildServer   = "adc-01.new.lab.local"                       # Child domain DC
$ParentServer  = "lab.local"                                  # Parent domain (or specific LAB DC)
$GCServer      = "DC-03.lab.local"                            # (optional) GC in LAB
$DriveName     = "ADNEW"                                      # PSDrive name for child
# --------------------------------------------

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

Write-Host "Looking up service account '$SvcUPN' in parent domain ($ParentServer)..."
# Use a UPN-friendly query (Filter/LDAPFilter), not -Identity
$user = Get-ADUser -Server $ParentServer -Filter "userPrincipalName -eq '$SvcUPN'" -Properties SID,SamAccountName
if (-not $user) {
    Write-Warning "Not found via $ParentServer. Trying Global Catalog $GCServer:3268..."
    $user = Get-ADUser -Server "$GCServer`:3268" -LDAPFilter "(userPrincipalName=$SvcUPN)" -Properties SID,SamAccountName
}
if (-not $user) { throw "Could not find '$SvcUPN' anywhere in the forest." }

$sid = $user.SID
Write-Host "Resolved UPN to sAM: $($user.SamAccountName); SID: $sid"

# --- Bind PSDrive to CHILD domain ---
Write-Host "Binding to child DC '$ChildServer'..."
$rootDseChild = Get-ADRootDSE -Server $ChildServer
$defaultNC    = $rootDseChild.defaultNamingContext   # e.g. DC=new,DC=lab,DC=local

# Recreate drive cleanly
$existing = Get-PSDrive -Name $DriveName -PSProvider ActiveDirectory -ErrorAction SilentlyContinue
if ($existing) { Remove-PSDrive -Name $DriveName -Force }
New-PSDrive -Name $DriveName -PSProvider ActiveDirectory -Server $ChildServer -Root $defaultNC | Out-Null

# Build OU path RELATIVE to the drive root (avoid repeating the NC)
$rdnPath = if ($TargetOUDN -like "*,${defaultNC}") {
    $TargetOUDN.Substring(0, $TargetOUDN.Length - ("," + $defaultNC).Length)
} else {
    $TargetOUDN
}
$ouPath = "$DriveName`:\$rdnPath"
Write-Host "Resolved OU path: $ouPath"

# Verify the OU exists using AD cmdlet (targets CHILD via -Server)
try {
    $ou = Get-ADOrganizationalUnit -Server $ChildServer -Identity $TargetOUDN -ErrorAction Stop
} catch {
    throw "Target OU '$TargetOUDN' not found in child domain ($ChildServer). Check the DN."
}

# --- Resolve needed GUIDs dynamically from CHILD schema/config ---
$schemaNC = $rootDseChild.schemaNamingContext
$configNC = $rootDseChild.configurationNamingContext

function Get-SchemaGuid {
    param([Parameter(Mandatory)][string]$LdapDisplayName)
    $obj = Get-ADObject -Server $ChildServer -SearchBase $schemaNC `
        -LDAPFilter "(|(ldapDisplayName=$LdapDisplayName)(cn=$LdapDisplayName))" -Properties schemaIDGUID
    if (-not $obj) { throw "Schema object '$LdapDisplayName' not found." }
    [Guid]$obj.schemaIDGUID
}
function Get-ExtendedRightGuid {
    param([Parameter(Mandatory)][string]$RightDisplayName)
    $er = Get-ADObject -Server $ChildServer -SearchBase "CN=Extended-Rights,$configNC" `
        -LDAPFilter "(displayName=$RightDisplayName)" -Properties rightsGuid
    if (-not $er) { throw "Extended right '$RightDisplayName' not found." }
    [Guid]$er.rightsGuid
}

$guidUserClass       = Get-SchemaGuid -LdapDisplayName "user"
$guidGroupClass      = Get-SchemaGuid -LdapDisplayName "group"
$guidMemberAttribute = Get-SchemaGuid -LdapDisplayName "member"
$guidResetPassword   = Get-ExtendedRightGuid -RightDisplayName "Reset Password"
# $guidChangePassword  = Get-ExtendedRightGuid -RightDisplayName "Change Password"  # optional

# --- Read ACL, build ACEs, and write back ---
Write-Host "Reading ACL from child OU..."
$acl = Get-Acl -Path $ouPath

$ADRights  = [System.DirectoryServices.ActiveDirectoryRights]
$Inherit   = [System.DirectoryServices.ActiveDirectorySecurityInheritance]
$Allow     = [System.Security.AccessControl.AccessControlType]::Allow

# 1) Create User objects under the OU
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::CreateChild, $Allow, $guidUserClass, $Inherit::Descendents)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Create User objects"

# 2) Delete User objects (often paired with Create)
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::DeleteChild, $Allow, $guidUserClass, $Inherit::Descendents)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Delete User objects"

# 3) Reset user passwords (extended right) scoped to User class
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::ExtendedRight, $Allow, $guidResetPassword, $Inherit::Descendents, $guidUserClass)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Reset Password (User)"

# 4) Write all properties on User objects (ObjectType = Guid.Empty; scope via inheritedObjectType=user)
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::WriteProperty, $Allow, [Guid]::Empty, $Inherit::Descendents, $guidUserClass)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Write properties (User)"

# 5) Modify group membership (write 'member' attribute) on Group objects
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::WriteProperty, $Allow, $guidMemberAttribute, $Inherit::Descendents, $guidGroupClass)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Modify 'member' (Group)"

Write-Host "Writing updated ACL to child OU..."
Set-Acl -Path $ouPath -AclObject $acl

Write-Host "Delegation complete: $SvcUPN (LAB) now has delegated rights on $TargetOUDN (NEW)."
