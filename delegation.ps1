# ------------------ CONFIG ------------------
$TargetOUDN      = "OU=_AdminAccounts,DC=new,DC=lab,DC=local" # CHILD OU DN
$SvcUPN          = "svc_adapi@lab.local"                      # PARENT account UPN
$ChildServer     = "dc-01.new.lab.local"                      # Any reachable NEW DC
$ParentServer    = "lab.local"                                # LAB domain (or a specific LAB DC)
# --------------------------------------------

Import-Module ActiveDirectory

# 1) Find the parent account by UPN (Filter/LDAPFilter — not -Identity)
Write-Host "Looking up '$SvcUPN' in parent domain ($ParentServer)..."
$user = Get-ADUser -Server $ParentServer -Filter "userPrincipalName -eq '$SvcUPN'" -Properties SID
if (-not $user) {
  Write-Warning "Not found via $ParentServer. Trying the Global Catalog on the child DC (port 3268)..."
  $user = Get-ADUser -Server "$ChildServer`:3268" -LDAPFilter "(userPrincipalName=$SvcUPN)" -Properties SID
}
if (-not $user) { throw "Could not find '$SvcUPN' anywhere in the forest." }
$sid = $user.SID
Write-Host "Resolved UPN to sAM: $($user.SamAccountName); SID: $sid"

# 2) Bind an AD drive to the CHILD domain so Get/Set-Acl hit NEW
$driveName = "ADNEW"
if (-not (Get-PSDrive -Name $driveName -PSProvider ActiveDirectory -ErrorAction SilentlyContinue)) {
  New-PSDrive -Name $driveName -PSProvider ActiveDirectory -Server $ChildServer -Root "\" | Out-Null
}
$ouPath = "$driveName`:\$TargetOUDN"

# 3) Helper: resolve schema/extended-right GUIDs dynamically (no guesswork)
$rootDseChild = Get-ADRootDSE -Server $ChildServer
$schemaNC     = $rootDseChild.schemaNamingContext
$configNC     = $rootDseChild.configurationNamingContext

function Get-SchemaGuid {
  param([string]$LdapDisplayName)
  $obj = Get-ADObject -Server $ChildServer -SearchBase $schemaNC -LDAPFilter "(|(ldapDisplayName=$LdapDisplayName)(cn=$LdapDisplayName))" -Properties schemaIDGUID
  if (-not $obj) { throw "Schema object '$LdapDisplayName' not found." }
  # Convert byte[] to Guid
  [Guid]::new(($obj.schemaIDGUID | ForEach-Object ToString "x2") -join "")
}

function Get-ExtendedRightGuid {
  param([string]$RightDisplayName)
  $searchBase = "CN=Extended-Rights,$configNC"
  $er = Get-ADObject -Server $ChildServer -SearchBase $searchBase -LDAPFilter "(displayName=$RightDisplayName)" -Properties rightsGuid
  if (-not $er) { throw "Extended right '$RightDisplayName' not found." }
  [Guid]$er.rightsGuid
}

# Resolve the GUIDs we need
$guidUserClass        = Get-SchemaGuid -LdapDisplayName "user"
$guidGroupClass       = Get-SchemaGuid -LdapDisplayName "group"
$guidMemberAttribute  = Get-SchemaGuid -LdapDisplayName "member"
$guidPwdReset         = Get-ExtendedRightGuid -RightDisplayName "Reset Password"
$guidUserChangePwd    = Get-ExtendedRightGuid -RightDisplayName "Change Password"  # often delegated too

# 4) Read existing ACL from child OU
Write-Host "Reading ACL from child OU: $TargetOUDN on $ChildServer ..."
$acl = Get-Acl $ouPath

# 5) Build ACEs
$inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
$allow = [System.Security.AccessControl.AccessControlType]::Allow

# 5.1 Create User objects under the OU
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "CreateChild", $allow, $guidUserClass, $inh)
$acl.AddAccessRule($ace)

# 5.2 Delete User objects (often paired with Create)
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "DeleteChild", $allow, $guidUserClass, $inh)
$acl.AddAccessRule($ace)

# 5.3 Reset user passwords (extended right)
$rights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, $allow, $guidPwdReset, $inh)
$acl.AddAccessRule($ace)

# 5.4 (Optional) Allow setting "Change Password" (rare for service admins, uncomment if desired)
# $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, $allow, $guidUserChangePwd, $inh)
# $acl.AddAccessRule($ace)

# 5.5 Write selected user properties (example: "write all properties" on user objects)
$rights = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, $allow, [Guid]::Empty, $inh)
$acl.AddAccessRule($ace)

# 5.6 Add/Remove users from groups (write 'member' on group objects)
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, $allow, $guidMemberAttribute, $inh)
$acl.AddAccessRule($ace)

# 6) Commit ACL back to the CHILD OU
Write-Host "Writing updated ACL to child OU..."
Set-Acl -Path $ouPath -AclObject $acl

Write-Host "Delegation complete: $SvcUPN (LAB) now has delegated rights on $TargetOUDN (NEW)."
