using System.ComponentModel.DataAnnotations;

namespace KeyStone.Models;

// --- Request Models ---

public class CreateUserRequest
{
    [Required]
    public string Domain { get; set; } = string.Empty;
    [Required]
    public string SamAccountName { get; set; } = string.Empty;
    [Required]
    public string FirstName { get; set; } = string.Empty;
    [Required]
    public string LastName { get; set; } = string.Empty;
    public string? DateOfBirth { get; set; }
    [RegularExpression(@"^\+966\d{9}$", ErrorMessage = "Mobile number must be in the format +966xxxxxxxxx")]
    public string? MobileNumber { get; set; }
    public bool CreateAdminAccount { get; set; }
    public List<string> OptionalGroups { get; set; } = new();
    // MODIFIED START // Added property to carry selected privilege groups for the -a account. This fixes CS1061. - 2025-09-26 11:55 PM
    public List<string> PrivilegeGroups { get; set; } = new();
    // MODIFIED END // Added property to carry selected privilege groups for the -a account. This fixes CS1061. - 2025-09-26 11:55 PM
}

public class UpdateUserRequest
{
    [Required]
    public string Domain { get; set; } = string.Empty;
    [Required]
    public string SamAccountName { get; set; } = string.Empty;
    public string? DateOfBirth { get; set; }
    [RegularExpression(@"^\+966\d{9}$", ErrorMessage = "Mobile number must be in the format +966xxxxxxxxx")]
    public string? MobileNumber { get; set; }
    public bool HasAdminAccount { get; set; }
    public List<string> OptionalGroups { get; set; } = new();
}

public class UserActionRequest
{
    [Required]
    public string Domain { get; set; } = string.Empty;
    [Required]
    public string SamAccountName { get; set; } = string.Empty;
}

public class ResetAdminPasswordRequest
{
    [Required]
    public string Domain { get; set; } = string.Empty;
    [Required]
    public string SamAccountName { get; set; } = string.Empty;
}

// --- Response Models ---

public class CreateUserResponse
{
    public string SamAccountName { get; set; } = string.Empty;
    public string? InitialPassword { get; set; }
    public string? AdminAccountName { get; set; }
    public string? AdminInitialPassword { get; set; }
}

public class UserListItem
{
    public string SamAccountName { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public bool IsEnabled { get; set; }
    public bool HasAdminAccount { get; set; }
}

public class UserDetailModel
{
    public string SamAccountName { get; set; } = string.Empty;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? DisplayName { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? EmailAddress { get; set; }
    public string? DateOfBirth { get; set; }
    public string? MobileNumber { get; set; }
    public bool IsEnabled { get; set; }
    public bool IsLockedOut { get; set; }
    public bool HasAdminAccount { get; set; }
    public List<string> MemberOf { get; set; } = new();
}