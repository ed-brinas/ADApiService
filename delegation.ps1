<#
Delegation: Parent NCC\svc-ad-adm-portal manages OU in child EMS

Grants:
 - Create/Delete User objects
 - Reset Password (extended right) on users
 - Write all properties on users
 - Modify group membership (write 'member' on groups)
#>


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

Write-Host "Looking up service account '$SvcUPN' in parent domain ($ParentServer)..."
# Use UPN-friendly lookup (Filter/LDAPFilter), not -Identity
$user = Get-ADUser -Server $ParentServer -Filter "userPrincipalName -eq '$SvcUPN'" -Properties SID,SamAccountName
if (-not $user) {
    Write-Warning "Not found via $ParentServer. Trying Global Catalog $GCServer:3268..."
    $user = Get-ADUser -Server "$GCServer`:3268" -LDAPFilter "(userPrincipalName=$SvcUPN)" -Properties SID,SamAccountName
}
if (-not $user) { throw "Could not find '$SvcUPN' anywhere in the forest." }

$sid = $user.SID
Write-Host "Resolved UPN to sAM: $($user.SamAccountName); SID: $sid"

# --- CHILD forest context (schema/config come from CHILD) ---
Write-Host "Querying child DC '$ChildServer' for schema/config NCs..."
$rootDseChild = Get-ADRootDSE -Server $ChildServer
$schemaNC     = $rootDseChild.schemaNamingContext
$configNC     = $rootDseChild.configurationNamingContext

# Verify target OU exists in CHILD
Write-Host "Verifying target OU in CHILD..."
$null = Get-ADOrganizationalUnit -Server $ChildServer -Identity $TargetOUDN -ErrorAction Stop

# --- Resolve GUIDs in CHILD (dynamic; no hardcoding) ---
function Get-SchemaGuid {
    param([Parameter(Mandatory)][string]$LdapDisplayName)
    $obj = Get-ADObject -Server $ChildServer -SearchBase $schemaNC `
           -LDAPFilter "(|(ldapDisplayName=$LdapDisplayName)(cn=$LdapDisplayName))" -Properties schemaIDGUID
    if (-not $obj) { throw "Schema object '$LdapDisplayName' not found in $schemaNC." }
    [Guid]$obj.schemaIDGUID
}
function Get-ExtendedRightGuid {
    param([Parameter(Mandatory)][string]$RightDisplayName)
    $er = Get-ADObject -Server $ChildServer -SearchBase "CN=Extended-Rights,$configNC" `
          -LDAPFilter "(displayName=$RightDisplayName)" -Properties rightsGuid
    if (-not $er) { throw "Extended right '$RightDisplayName' not found in Extended-Rights." }
    [Guid]$er.rightsGuid
}

$guidUserClass       = Get-SchemaGuid -LdapDisplayName "user"
$guidGroupClass      = Get-SchemaGuid -LdapDisplayName "group"
$guidMemberAttribute = Get-SchemaGuid -LdapDisplayName "member"
$guidResetPassword   = Get-ExtendedRightGuid -RightDisplayName "Reset Password"
# $guidChangePassword  = Get-ExtendedRightGuid -RightDisplayName "Change Password"  # optional

# --- Bind to CHILD OU via ADSI and work with the DACL directly ---
$ldapPath = "LDAP://$ChildServer/$TargetOUDN"
Write-Host "Binding to CHILD OU via ADSI: $ldapPath"
$de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)

# Try to explicitly load security descriptor (works on most builds even without Options.SecurityMasks)
try {
    $null = $de.RefreshCache(@('ntSecurityDescriptor'))
} catch {
    Write-Verbose "RefreshCache(ntSecurityDescriptor) not supported here; continuing."
}

# Read current ACL (returns an ActiveDirectorySecurity)
$acl = $de.ObjectSecurity
if (-not $acl) { throw "Failed to read ObjectSecurity from '$ldapPath'." }

$ADRights = [System.DirectoryServices.ActiveDirectoryRights]
$Inherit  = [System.DirectoryServices.ActiveDirectorySecurityInheritance]
$Allow    = [System.Security.AccessControl.AccessControlType]::Allow

# ---- Rules -------------------------------------------------------------

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

# 3) Reset Password (extended right) scoped to User class
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::ExtendedRight, $Allow, $guidResetPassword, $Inherit::Descendents, $guidUserClass)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Reset Password (User)"

# 4) Write all properties on User objects
#    (ObjectType = Guid.Empty => all properties; scope via inheritedObjectType=user)
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::WriteProperty, $Allow, [Guid]::Empty, $Inherit::Descendents, $guidUserClass)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Write properties (User)"

# 5) Modify group membership (write 'member' attribute) on Group objects
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ($sid, $ADRights::WriteProperty, $Allow, $guidMemberAttribute, $Inherit::Descendents, $guidGroupClass)
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Modify 'member' (Group)"

# (Optional) Allow "Change Password" extended right on user objects
# $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
#     ($sid, $ADRights::ExtendedRight, $Allow, $guidChangePassword, $Inherit::Descendents, $guidUserClass)
# $acl.AddAccessRule($ace)
# Write-Host "Rule Added: Change Password (User) (optional)"

# Write ACL back
Write-Host "Committing ACL to CHILD OU..."
$de.ObjectSecurity = $acl
$de.CommitChanges()

Write-Host "Delegation complete: $SvcUPN (PARENT) now has delegated rights on $TargetOUDN (CHILD)."
