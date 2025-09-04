using System.ComponentModel.DataAnnotations;

namespace ADApiService.Models;

// Data Transfer Object for creating a new user
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
    [Required]
    public string Password { get; set; } = string.Empty;
    public List<string>? OptionalGroups { get; set; }
}

// Data Transfer Object for listing users
public class UserListItem
{
    public string DisplayName { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public string? EmailAddress { get; set; }
    public bool Enabled { get; set; }
}

// Data Transfer Object for the current authenticated user's context
public class UserContext
{
    public string Name { get; set; } = string.Empty;
    public bool IsHighPrivilege { get; set; }
}

// Data Transfer Object for resetting a password
public class ResetPasswordRequest
{
    [Required]
    public string Domain { get; set; } = string.Empty;
    [Required]
    public string SamAccountName { get; set; } = string.Empty;
    [Required]
    public string NewPassword { get; set; } = string.Empty;
}

