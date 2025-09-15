# --- Configuration ---
# The distinguished name of the OU in the CHILD domain where permissions will be applied.
$targetOU = "OU=_AdminAccounts,DC=new,DC=lab,DC=local" 

# The SamAccountName of the service account which exists in the PARENT domain.
$serviceAccount = "svc_adapi"

# The fully qualified domain name of a domain controller in the PARENT domain.
$parentDomainController = "DC-03.lab.local"

# --- Main Script ---

# Step 1: Get the service account's SID from the PARENT domain controller.
Write-Host "Fetching SID for '$serviceAccount' from '$parentDomainController'..."
$sid = (Get-ADUser -Identity $serviceAccount -Server $parentDomainController).SID
if ($null -eq $sid) {
    Write-Error "Could not find service account '$serviceAccount' in domain '$parentDomainController'. Please check the name and domain controller."
    return
}
Write-Host "Successfully found SID for '$serviceAccount'."

# Step 2: Get the current ACL from the target OU. 
# The AD provider automatically routes this to the correct domain controller based on the DN.
Write-Host "Fetching ACL for '$targetOU'..."
$acl = Get-Acl "AD:\$targetOU"

# Step 3: Define all the necessary permissions (Access Control Entries).

# 3.1: Permission to Create User Objects in this OU
$objectType = [System.Guid]::new("bf967aba-0de6-11d0-a329-00c04fd8d5cd") # GUID for "User" object
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "CreateChild", "Allow", $objectType, "Descendents")
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Create User Objects"

# 3.2: Permission to Reset User Passwords
$rights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
$extendedRightGuid = [System.Guid]::new("00299571-280d-11d1-a768-00aa006e0529") # GUID for "Reset Password"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, "Allow", $extendedRightGuid, "Descendents")
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Reset User Passwords"

# 3.3: Permission to Modify User Account Properties (Enable/Disable, Expiration)
$rights = "WriteProperty"
$propertyGuid = [System.Guid]::new("4c164200-20c0-11d0-a768-00aa006e0529") # GUID for "Account Restrictions"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, "Allow", $propertyGuid, "Descendents")
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Modify User Account Properties"

# 3.4: Permission to Modify User's Public Information (Display Name, etc.)
$propertyGuid = [System.Guid]::new("e45795b2-9455-11d1-aebd-0000f80367c1") # GUID for "Public Information"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, "Allow", $propertyGuid, "Descendents")
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Modify User Public Information"

# 3.5: Permission to Add/Remove Users from Groups
$propertyGuid = [System.Guid]::new("bf9679c0-0de6-11d0-a329-00c04fd8d5cd") # GUID for "Member" attribute of a group
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, "Allow", $propertyGuid, "Descendents")
$acl.AddAccessRule($ace)
Write-Host "Rule Added: Modify Group Membership"

# Step 4: Apply the modified ACL to the OU.
Write-Host "Applying new ACL to '$targetOU'..."
Set-Acl -Path "AD:\$targetOU" -AclObject $acl
Write-Host "Delegation complete for '$serviceAccount' on '$targetOU'."
