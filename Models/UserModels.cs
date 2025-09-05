using System.ComponentModel.DataAnnotations;

namespace ADApiService.Models;

#region API Request Models

/// <summary>
/// Represents the data required to create a new user account.
/// </summary>
public class CreateUserRequest
{
    [Required] public string Domain { get; set; } = string.Empty;
    [Required] public string FirstName { get; set; } = string.Empty;
    [Required] public string LastName { get; set; } = string.Empty;
    [Required] public string SamAccountName { get; set; } = string.Empty;
    [Required] public string Password { get; set; } = string.Empty;
    public List<string>? OptionalGroups { get; set; }
    public bool CreateAdminAccount { get; set; }
}

/// <summary>
/// Represents the data required to update an existing user account.
/// </summary>
public class UpdateUserRequest
{
    [Required] public string Domain { get; set; } = string.Empty;
    [Required] public string SamAccountName { get; set; } = string.Empty;
    public List<string>? OptionalGroups { get; set; }
    public bool ManageAdminAccount { get; set; }
}

/// <summary>
/// Represents the data required to reset a user's password.
/// </summary>
public class ResetPasswordRequest
{
    [Required] public string Domain { get; set; } = string.Empty;
    [Required] public string SamAccountName { get; set; } = string.Empty;
    [Required] public string NewPassword { get; set; } = string.Empty;
}

/// <summary>
/// Represents a generic request to perform an action on a user account.
/// </summary>
public class UserActionRequest
{
    [Required] public string Domain { get; set; } = string.Empty;
    [Required] public string SamAccountName { get; set; } = string.Empty;
}

#endregion

#region API Response Models

/// <summary>
/// Represents the summarized information for a user in a list.
/// </summary>
public class UserListItem
{
    public string DisplayName { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public string? EmailAddress { get; set; }
    public bool Enabled { get; set; }
    public bool HasAdminAccount { get; set; }
}

/// <summary>
/// Represents the detailed information for a single user, used for the edit form.
/// </summary>
public class UserDetailModel
{
    public string DisplayName { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public bool HasAdminAccount { get; set; }
    public List<string> MemberOf { get; set; } = [];
}

/// <summary>
/// Represents the authenticated user's context, including their permissions.
/// </summary>
public class UserContextModel
{
    public string Name { get; set; } = string.Empty;
    public bool IsHighPrivilege { get; set; }
    public bool CanCreateUsers { get; set; }
    public List<string> Groups { get; set; } = [];
}

#endregion

