using System.ComponentModel.DataAnnotations;

namespace ADApiService.Models;

#region API Payloads

/// <summary>
/// Represents a user in a search result list.
/// </summary>
public class UserListItem
{
    public string? DisplayName { get; set; }
    public string? SamAccountName { get; set; }
    public string? EmailAddress { get; set; }
    public bool Enabled { get; set; }
    public bool HasAdminAccount { get; set; }
    public DateTime? AccountExpirationDate { get; set; }
}

/// <summary>
/// Represents the full details for a single user for editing.
/// </summary>
public class UserDetailModel
{
    public string DisplayName { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public bool HasAdminAccount { get; set; }
    public List<string> MemberOf { get; set; } = new();
    public DateTime? AccountExpirationDate { get; set; }
    public bool CanAutoResetPassword { get; set; } 
}

/// <summary>
/// Defines the data required to update a user's properties.
/// </summary>
public class UpdateUserRequest
{
    [Required]
    public string Domain { get; set; } = string.Empty;
    [Required]
    public string SamAccountName { get; set; } = string.Empty;
    [Required]
    public string FirstName { get; set; } = string.Empty;
    [Required]
    public string LastName { get; set; } = string.Empty;
    public List<string>? OptionalGroups { get; set; }
    public bool ManageAdminAccount { get; set; }
    [Required]
    public DateTime AccountExpirationDate { get; set; }
}

/// <summary>
/// Defines the data required to reset an admin (-a) account's password.
/// </summary>
public class ResetAdminPasswordRequest
{
    [Required]
    public string Domain { get; set; } = string.Empty;
    [Required]
    public string SamAccountName { get; set; } = string.Empty;
}

#endregion

#region Existing Models (Unchanged)
public class CreateUserRequest { [Required] public string Domain { get; set; } = string.Empty; [Required] public string FirstName { get; set; } = string.Empty; [Required] public string LastName { get; set; } = string.Empty; [Required] public string SamAccountName { get; set; } = string.Empty; public List<string>? OptionalGroups { get; set; } public bool CreateAdminAccount { get; set; } [Required] public DateTime AccountExpirationDate { get; set; } }
public class CreateUserResponse { public string Message { get; set; } = string.Empty; public UserAccountDetails? UserAccount { get; set; } public AdminAccountDetails? AdminAccount { get; set; } public List<string> GroupsAssociated { get; set; } = new(); }
public class UserAccountDetails { public string SamAccountName { get; set; } = string.Empty; public string DisplayName { get; set; } = string.Empty; public string UserPrincipalName { get; set; } = string.Empty; public string InitialPassword { get; set; } = string.Empty; }
public class AdminAccountDetails { public string SamAccountName { get; set; } = string.Empty; public string DisplayName { get; set; } = string.Empty; public string UserPrincipalName { get; set; } = string.Empty; public string InitialPassword { get; set; } = string.Empty; }
public class UserActionRequest { [Required] public string Domain { get; set; } = string.Empty; [Required] public string SamAccountName { get; set; } = string.Empty; }
#endregion

