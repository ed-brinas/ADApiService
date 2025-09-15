# --- Configuration ---
# The distinguished name of the OU in the CHILD domain.
$targetOU = "OU=_Managed,DC=new,DC=lab,DC=local" 

# The SamAccountName of the service account in the PARENT domain.
$serviceAccount = "svc_adapi"

# The fully qualified domain name of a domain controller in the PARENT domain.
$parentDomainController = "DC01.lab.local" 

# The fully qualified domain name of a domain controller in the CHILD domain.
$childDomainController = "NEWDC01.new.lab.local"

# --- Main Script ---

# Step 1: Get the service account's SID from the PARENT domain.
Write-Host "Fetching SID for '$serviceAccount' from '$parentDomainController'..."
$sid = (Get-ADUser -Identity $serviceAccount -Server $parentDomainController).SID
if ($null -eq $sid) {
    Write-Error "Could not find service account '$serviceAccount' in domain '$parentDomainController'. Please check the name and domain."
    return
}

# Step 2: Get the current ACL for the target OU from the CHILD domain.
Write-Host "Fetching ACL for '$targetOU' from '$childDomainController'..."
$acl = Get-Acl "AD:\$targetOU" -Server $childDomainController

# ... (The rest of the script for defining and adding the access rules remains exactly the same) ...

# 1. Permission to Create User Objects in this OU
$objectType = [System.Guid]::new("bf967aba-0de6-11d0-a329-00c04fd8d5cd") # GUID for "User" object type
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, 
    "CreateChild", 
    "Allow", 
    $objectType, 
    "Descendents"
)
$acl.AddAccessRule($ace)
Write-Host "Granted: Create User Objects"

# 2. Permission to Reset User Passwords
$objectType = [System.Guid]::new("00299570-246d-11d0-a768-00aa006e0529") # GUID for "User" object type
$rights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
$extendedRightGuid = [System.Guid]::new("00299571-280d-11d1-a768-00aa006e0529") # GUID for "Reset Password" extended right
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, 
    $rights, 
    "Allow", 
    $extendedRightGuid, 
    "Descendents"
)
$acl.AddAccessRule($ace)
Write-Host "Granted: Reset User Passwords"

# 3. Permission to Modify User Account Properties
$objectType = [System.Guid]::new("bf967aba-0de6-11d0-a329-00c04fd8d5cd") # GUID for "User" object type
$rights = "WriteProperty"
$propertyGuid = [System.Guid]::new("4c164200-20c0-11d0-a768-00aa006e0529") # GUID for "Account Restrictions" property set
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, 
    $rights, 
    "Allow", 
    $propertyGuid, 
    "Descendents"
)
$acl.AddAccessRule($ace)
Write-Host "Granted: Modify User Account Properties"

# 4. Permission to Modify User's Public Information
$objectType = [System.Guid]::new("bf967aba-0de6-11d0-a329-00c04fd8d5cd") # GUID for "User" object type
$rights = "WriteProperty"
$propertyGuid = [System.Guid]::new("e45795b2-9455-11d1-aebd-0000f80367c1") # GUID for "Public Information" property set
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, 
    $rights, 
    "Allow", 
    $propertyGuid, 
    "Descendents"
)
$acl.AddAccessRule($ace)
Write-Host "Granted: Modify User Public Information"

# 5. Permission to Add/Remove Users from Groups
$objectType = [System.Guid]::new("bf967a9c-0de6-11d0-a329-00c04fd8d5cd") # GUID for "Group" object type
$rights = "WriteProperty"
$propertyGuid = [System.Guid]::new("bf9679c0-0de6-11d0-a329-00c04fd8d5cd") # GUID for "Member" attribute
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, 
    $rights, 
    "Allow", 
    $propertyGuid, 
    "Descendents"
)
$acl.AddAccessRule($ace)
Write-Host "Granted: Modify Group Membership"


# Step 3: Apply the new ACL to the OU in the CHILD domain.
Write-Host "Applying new ACL to '$targetOU' on '$childDomainController'..."
Set-Acl -Path "AD:\$targetOU" -AclObject $acl -Server $childDomainController
Write-Host "Delegation complete for '$serviceAccount' on '$targetOU'."
