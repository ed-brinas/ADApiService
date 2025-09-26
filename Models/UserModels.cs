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
    public string? DateOfBirth { get; set; } // New field
    // MODIFIED START // Added RegularExpression for validation - 2025-09-26 10:42 PM
    [RegularExpression(@"^\+966\d{9}$", ErrorMessage = "Mobile number must be in the format +966xxxxxxxxx")]
    // MODIFIED END // Added RegularExpression for validation - 2025-09-26 10:42 PM
    public string? MobileNumber { get; set; } // New field
    public bool CreateAdminAccount { get; set; }
    public List<string> OptionalGroups { get; set; } = new();
}

public class UpdateUserRequest
{
    [Required]
    public string Domain { get; set; } = string.Empty;
    [Required]
    public string SamAccountName { get; set; } = string.Empty;
    public string? DateOfBirth { get; set; } // New field
    // MODIFIED START // Added RegularExpression for validation - 2025-09-26 10:42 PM
    [RegularExpression(@"^\+966\d{9}$", ErrorMessage = "Mobile number must be in the format +966xxxxxxxxx")]
    // MODIFIED END // Added RegularExpression for validation - 2025-09-26 10:42 PM
    public string? MobileNumber { get; set; } // New field
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
    public string? DateOfBirth { get; set; } // New field
    public string? MobileNumber { get; set; } // New field
    public bool IsEnabled { get; set; }
    public bool IsLockedOut { get; set; }
    public bool HasAdminAccount { get; set; }
    public List<string> MemberOf { get; set; } = new();
}