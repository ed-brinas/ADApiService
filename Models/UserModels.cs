using System.ComponentModel.DataAnnotations;

namespace ADApiService.Models;

#region API Payloads

/// <summary>
/// Defines the data required to create a new user account.
/// </summary>
public class CreateUserRequest
{
    /// <summary>The target domain for the new user (e.g., "lab.local").</summary>
    [Required]
    public string Domain { get; set; } = string.Empty;
    /// <summary>The user's first name.</summary>
    [Required]
    public string FirstName { get; set; } = string.Empty;
    /// <summary>The user's last name.</summary>
    [Required]
    public string LastName { get; set; } = string.Empty;
    /// <summary>The user's logon name (sAMAccountName).</summary>
    [Required]
    public string SamAccountName { get; set; } = string.Empty;
    
    /// <summary>
    /// The password for the new user. If left null or empty, a strong random password will be generated.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>A list of optional groups to add the new user to. Requires high-privilege access.</summary>
    public List<string>? OptionalGroups { get; set; }
    /// <summary>Whether to create an associated administrative account (-a). Requires high-privilege access.</summary>
    public bool CreateAdminAccount { get; set; }
}

/// <summary>
/// Represents the detailed response after a user is successfully created, including generated passwords.
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


/// <summary>
/// Defines the data required to update a user's group memberships or admin account status.
/// </summary>
public class UpdateUserRequest 
{ 
    [Required] public string Domain { get; set; } = string.Empty; 
    [Required] public string SamAccountName { get; set; } = string.Empty; 
    public List<string>? OptionalGroups { get; set; } 
    public bool ManageAdminAccount { get; set; } 
}

/// <summary>
/// Defines the data required to reset a user's password.
/// </summary>
public class ResetPasswordRequest 
{ 
    [Required] public string Domain { get; set; } = string.Empty; 
    [Required] public string SamAccountName { get; set; } = string.Empty; 
    [Required] public string NewPassword { get; set; } = string.Empty; 
}

/// <summary>
/// Defines the data for a simple user action, such as unlocking an account.
/// </summary>
public class UserActionRequest 
{ 
    [Required] public string Domain { get; set; } = string.Empty; 
    [Required] public string SamAccountName { get; set; } = string.Empty; 
}

#endregion

#region API Responses

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
}

/// <summary>
/// Represents the full details of a single user for editing.
/// </summary>
public class UserDetailModel 
{ 
    public string DisplayName { get; set; } = string.Empty; 
    public string SamAccountName { get; set; } = string.Empty; 
    public bool HasAdminAccount { get; set; } 
    public List<string> MemberOf { get; set; } = new(); 
}

/// <summary>
/// Represents a standardized API error response.
/// </summary>
public class ApiError 
{ 
    public string Message { get; set; } 
    public string? Detail { get; set; } 
    public ApiError(string message, string? detail = null) { Message = message; Detail = detail; } 
}

#endregion

