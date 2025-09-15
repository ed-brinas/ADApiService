<# 
Delegate svc_adapi@lab.local (PARENT) to manage OU in new.lab.local (CHILD)

What it does:
  - Looks up the parent-domain service account by UPN (not -Identity)
  - Creates an AD PSDrive rooted at the child domain's defaultNamingContext
  - Resolves schema and extended-right GUIDs dynamically (no hardcoded GUIDs)
  - Grants: Create/Delete User, Reset Password, Write properties on Users,
            Modify 'member' on Groups (add/remove users to groups)
#>

# ------------------ CONFIG ------------------
$TargetOUDN    = "OU=_AdminAccounts,DC=NEW,DC=LAB,DC=LOCAL"  # Child OU DN
$SvcUPN        = "svc_adapi@lab.local"                       # Parent svc account UPN
$ChildServer   = "mve-prd-adc-01.new.lab.local"              # A reachable NEW domain DC
$ParentServer  = "lab.local"                                 # LAB domain (or specific LAB DC)
$GCServer      = "DC-03.lab.local"                           # Optional: a GC-capable DC in LAB
# --------------------------------------------

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory

Write-Host "Looking up service account '$SvcUPN' in parent domain ($ParentServer)..."
# Prefer a UPN-friendly filter. Do NOT use -Identity for UPNs.
$user = Get-ADUser -Server $ParentServer -Filter "userPrincipalName -eq '$SvcUPN'" -Properties SID,SamAccountName
if (-not $user) {
    Write-Warning "Not found via $ParentServer. Trying Global Catalog on $GCServer:3268..."
    $user = Get-ADUser -Server "$GCServer`:3268" -LDAPFilter "(userPrincipalName=$SvcUPN)" -Properties SID,SamAccountName
}
if (-not $user) { throw "Could not find '$SvcUPN' anywhere in the forest." }

$sid = $user.SID
Write-Host "Resolved UPN to sAM: $($user.SamAccountName); SID: $sid"

# Bind an AD PSDrive to the CHILD domain so Get-Acl/Set-Acl hit NEW
Write-Host "Binding to child DC '$ChildServer'..."
$rootDseChild = Get-ADRootDSE -Server $ChildServer
$defaultNC    = $rootDseChild.defaultNamingContext  # e.g. DC=new,DC=lab,DC=local

$driveName = "ADNEW"
if (Get-PSDrive -Name $driveName -PSProvider ActiveDirectory -ErrorAction SilentlyContinue) {
    Remove-PSDrive -Name $driveName -Force
}
New-PSDrive -Name $driveName -PSProvider ActiveDirectory -Server $ChildServer -Root $defaultNC | Out-Null

$ouPath = "$driveName`:\$TargetOUDN"
if (-not (Test-Path $ouPath)) {
    throw "Target OU not found at '$ouPath'. Verify DN and child domain."
}
Write-Host "Target OU resolved: $ouPath"

# Helper functions to resolve GUIDs dynamically
$schemaNC = $rootDseChild.schemaNamingContext
$configNC = $rootDseChild.configurationNamingContext

function Get-SchemaGuid {
    param([Parameter(Mandatory)][string]$LdapDisplayName)
    $obj = Get-ADObject -Server $ChildServer -SearchBase $schemaNC `
        -LDAPFilter "(|(ldapDisplayName=$LdapDisplayName)(cn=$LdapDisplayName))" -Properties schemaIDGUID
    if (-not $obj) { throw "Schema object '$LdapDisplayName' not found in $schemaNC." }
    [Guid]$obj.schemaIDGUID
}

function Get-ExtendedRightGuid {
    param([Parameter(Mandatory)][string]$RightDisplayName)
    $searchBase = "CN=Extended-Rights,$configNC"
    $er = Get-ADObject -Server $ChildServer -SearchBase $searchBase `
        -LDAPFilter "(displayName=$RightDisplayName)" -Properties rightsGuid
    if (-not $er) { throw "Extended right '$RightDisplayName' not found in $searchBase." }
    [Guid]$er.rightsGuid
}

# Resolve GUIDs we need
$guidUserClass       = Get-SchemaGuid -LdapDisplayName "user"
$guidGroupClass      = Get-SchemaGuid -LdapDisplayName "group"
$guidMemberAttribute = Get-SchemaGuid -LdapDisplayName "member"
$guidResetPassword   = Get-ExtendedRightGuid -RightDisplayName "Reset Password"
# $guidChangePassword  = Get-ExtendedRightGuid -RightDisplayName "Change Password"  # (optional)

# Prepare to edit ACL
Write-Host "Reading ACL from child OU..."
$acl = Get-Acl -Path $ouPath

$ADRights  = [System.DirectoryServices.ActiveDirectoryRights]
$Inherit   = [System.DirectoryServices.ActiveDirectorySecurityInheritance]
$Allow     = [System.Security.AccessControl.AccessControlType]::Allow

# ---- Rules -------------------------------------------------------------

# 1) Create User objects under the OU
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::CreateChild, $Allow, $guidUserClass, $Inherit::Descendents)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Create User objects"

# 2) Delete User objects under the OU (often paired with Create)
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::DeleteChild, $Allow, $guidUserClass, $Inherit::Descendents)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Delete User objects"

# 3) Reset user passwords (extended right), scoped to User objects
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::ExtendedRight, $Allow, $guidResetPassword, $Inherit::Descendents, $guidUserClass)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Reset User Passwords"

# 4) Write all properties on User objects (scope via inheritedObjectType=user)
#    (ObjectType = Guid.Empty => all properties)
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::WriteProperty, $Allow, [Guid]::Empty, $Inherit::Descendents, $guidUserClass)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Write properties on User objects"

# 5) Modify Group membership (write 'member' attribute) on Group objects
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::WriteProperty, $Allow, $guidMemberAttribute, $Inherit::Descendents, $guidGroupClass)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Modify 'member' on Group objects"

# (Optional) Allow "Change Password" extended right on user objects
# $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
#     ($sid, $ADRights::ExtendedRight, $Allow, $guidChangePassword, $Inherit::Descendents, $guidUserClass)
# $acl.AddAccessRule($ace)
# Write-Host "Rule Added: Change Password (optional)"

# -----------------------------------------------------------------------

Write-Host "Writing updated ACL to child OU..."
Set-Acl -Path $ouPath -AclObject $acl

Write-Host "Delegation complete: $SvcUPN (LAB) now has delegated rights on $TargetOUDN (NEW)."
