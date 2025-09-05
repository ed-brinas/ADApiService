using System.ComponentModel.DataAnnotations;

namespace ADApiService.Models;

public class CreateUserModel
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
    public List<string> OptionalGroups { get; set; } = new();
    public bool CreateAdminAccount { get; set; }
}

public class UserListItem
{
    public string DisplayName { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public string? EmailAddress { get; set; }
    public bool Enabled { get; set; }
}

// NEW: Full details for a single user for the edit form
public class UserDetailModel
{
    public string DisplayName { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public bool HasAdminAccount { get; set; }
    public List<string> MemberOf { get; set; } = new();
}

// NEW: Data sent from the frontend to update a user
public class UpdateUserRequest
{
    [Required]
    public string Domain { get; set; } = string.Empty;
    [Required]
    public string SamAccountName { get; set; } = string.Empty;
    public List<string>? OptionalGroups { get; set; }
    public bool CreateAdminAccount { get; set; }
}
