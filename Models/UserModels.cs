using System.ComponentModel.DataAnnotations;

namespace ADApiService.Models
{
    public class CreateUserRequest
    {
        [Required]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [MinLength(6)]
        public string SamAccountName { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [MinLength(8)]
        public string Password { get; set; } = string.Empty;

        [Required]
        public string Domain { get; set; } = string.Empty;

        public List<string>? AdditionalGroups { get; set; }
    }
    
    public class UserResponse
    {
        public string? DistinguishedName { get; set; }
        public string? SamAccountName { get; set; }
        public string? DisplayName { get; set; }
        public string? UserPrincipalName { get; set; }
        public string? EmailAddress { get; set; }
        public bool? Enabled { get; set; }
        public DateTime? LastLogon { get; set; }
    }

    public class ResetPasswordRequest
    {
        [Required]
        public string SamAccountName { get; set; } = string.Empty;
        
        [Required]
        public string Domain { get; set; } = string.Empty;

        [Required]
        [MinLength(8)]
        public string NewPassword { get; set; } = string.Empty;
    }
    
    public class UnlockAccountRequest
    {
        [Required]
        public string SamAccountName { get; set; } = string.Empty;
        
        [Required]
        public string Domain { get; set; } = string.Empty;
    }
}

