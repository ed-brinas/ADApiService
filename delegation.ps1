# --- Configuration ---
# The distinguished name of the OU in THIS domain where permissions will be applied.
$targetOU = "OU=_AdminAccounts,DC=new,DC=lab,DC=local" 

# The full User Principal Name (UPN) of the service account from the PARENT domain.
$serviceAccountUPN = "svc_adapi@lab.local"

# The fully qualified domain name of a Global Catalog server in the PARENT domain.
# This is often the same as a regular domain controller.
$globalCatalog = "DC-03.lab.local"

# --- Main Script ---

# Step 1: Get the service account's SID by querying the Global Catalog in the parent domain.
Write-Host "Fetching SID for '$serviceAccountUPN' from Global Catalog server '$globalCatalog'..."
$user = Get-ADUser -Identity $serviceAccountUPN -Server $globalCatalog
if ($null -eq $user) {
    Write-Error "Could not find service account '$serviceAccountUPN' in the forest. Please check the UPN and Global Catalog server name."
    return
}
$sid = $user.SID
Write-Host "Successfully found SID for '$($user.SamAccountName)'."

# Step 2: Get the current ACL from the target OU. This is a local operation.
Write-Host "Fetching ACL for '$targetOU'..."
$acl = Get-Acl "AD:\$targetOU"

# Step 3: Define and add all necessary permissions.
# (This section remains unchanged)

# 3.1: Permission to Create User Objects
$objectType = [System.Guid]::new("bf967aba-0de6-11d0-a329-00c04fd8d5cd")
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "CreateChild", "Allow", $objectType, "Descendents")
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Create User Objects"

# 3.2: Permission to Reset User Passwords
$rights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
$extendedRightGuid = [System.Guid]::new("00299571-280d-11d1-a768-00aa006e0529")
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, "Allow", $extendedRightGuid, "Descendents")
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Reset User Passwords"

# 3.3: Permission to Modify User Account Properties
$rights = "WriteProperty"
$propertyGuid = [System.Guid]::new("4c164200-20c0-11d0-a768-00aa006e0529")
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, "Allow", $propertyGuid, "Descendents")
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Modify User Account Properties"

# 3.4: Permission to Modify User's Public Information
$propertyGuid = [System.Guid]::new("e45795b2-9455-11d1-aebd-0000f80367c1")
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, "Allow", $propertyGuid, "Descendents")
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Modify User Public Information"

# 3.5: Permission to Add/Remove Users from Groups
$propertyGuid = [System.Guid]::new("bf9679c0-0de6-11d0-a329-00c04fd8d5cd")
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, "Allow", $propertyGuid, "Descendents")
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Modify Group Membership"

# Step 4: Apply the modified ACL to the OU.
Write-Host "Applying new ACL to '$targetOU'..."
Set-Acl -Path "AD:\$targetOU" -AclObject $acl
Write-Host "Delegation complete for '$serviceAccountUPN' on '$targetOU'."
