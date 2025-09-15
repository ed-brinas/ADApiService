# --- Configuration ---
$targetOU = "OU=_Managed,DC=new,DC=lab,DC=local"
$serviceAccount = "svc_adapi"
$childDomainController = "NEWDC01.new.lab.local" # <-- Add the DC name here

# The SamAccountName of the service account.
$serviceAccount = "svc_adapi"

# --- Main Script ---
$sid = (Get-ADUser -Identity $serviceAccount -Server $childDomainController).SID
$acl = Get-Acl "AD:\$targetOU" -Server $childDomainController

# Define the specific permissions needed by the API.
# Each object represents a specific right to be granted.

# 1. Permission to Create User Objects in this OU
$objectType = [System.Guid]::new("bf967aba-0de6-11d0-a329-00c04fd8d5cd") # GUID for "User" object type
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, 
    "CreateChild", # The right to create objects
    "Allow", 
    $objectType, 
    "Descendents" # Apply to this OU and its children
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

# 3. Permission to Modify User Account Properties (Enable/Disable, Expiration)
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

# 4. Permission to Modify User's Public Information (Display Name, etc.)
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

# 5. Permission to Add/Remove Users from Groups (modifying the 'member' attribute of a group)
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

# Apply the new ACL to the OU
Set-Acl -Path "AD:\$targetOU" -AclObject $acl -Server $childDomainController
Write-Host "Delegation complete for '$serviceAccount' on '$targetOU'."

