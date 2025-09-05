using System.ComponentModel.DataAnnotations;

namespace ADApiService.Models;

#region API Payloads

/// <summary>
/// Defines the data required to create a new user account. The password will be generated automatically.
/// </summary>
public class CreateUserRequest
{
    [Required]
    public string Domain { get; set; } = string.Empty;
    [Required]
    public string FirstName { get; set; } = string.Empty;
    [Required]
    public string LastName { get; set; } = string.Empty;
    [Required]
    public string SamAccountName { get; set; } = string.Empty;
    public List<string>? OptionalGroups { get; set; }
    public bool CreateAdminAccount { get; set; }
}

/// <summary>
/// Represents the detailed response after a user is successfully created.
/// </summary>
public class CreateUserResponse
{
    public string Message { get; set; } = string.Empty;
    public UserAccountDetails? UserAccount { get; set; }
    public AdminAccountDetails? AdminAccount { get; set; }
    public List<string> GroupsAssociated { get; set; } = new();
}

/// <summary>
/// Contains details for a newly created standard user account.
/// </summary>
public class UserAccountDetails
{
    public string SamAccountName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string UserPrincipalName { get; set; } = string.Empty;
    public string InitialPassword { get; set; } = string.Empty;
}

/// <summary>
/// Contains details for a newly created associated admin account.
/// </summary>
public class AdminAccountDetails
{
    public string SamAccountName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string UserPrincipalName { get; set; } = string.Empty;
    public string InitialPassword { get; set; } = string.Empty;
}

#endregion

#region Existing Models (Unchanged)
public class UserListItem { public string? DisplayName { get; set; } public string? SamAccountName { get; set; } public string? EmailAddress { get; set; } public bool Enabled { get; set; } public bool HasAdminAccount { get; set; } }
public class UserDetailModel { public string DisplayName { get; set; } = string.Empty; public string SamAccountName { get; set; } = string.Empty; public bool HasAdminAccount { get; set; } public List<string> MemberOf { get; set; } = new(); }
public class UpdateUserRequest { [Required] public string Domain { get; set; } = string.Empty; [Required] public string SamAccountName { get; set; } = string.Empty; public List<string>? OptionalGroups { get; set; } public bool ManageAdminAccount { get; set; } }
public class UserActionRequest { [Required] public string Domain { get; set; } = string.Empty; [Required] public string SamAccountName { get; set; } = string.Empty; }
#endregion

