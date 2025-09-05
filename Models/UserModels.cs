using System.ComponentModel.DataAnnotations;

namespace ADApiService.Models
{
    // This is the definition of CreateUserRequest
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
        public bool CreateAdminAccount { get; set; }
    }

    public class UpdateUserRequest
    {
        [Required]
        public string Domain { get; set; } = string.Empty;
        [Required]
        public string SamAccountName { get; set; } = string.Empty;
        public List<string>? OptionalGroups { get; set; }
        public bool CreateAdminAccount { get; set; }
    }

    public class UserDetailModel
    {
        public string DisplayName { get; set; } = string.Empty;
        public string SamAccountName { get; set; } = string.Empty;
        public bool HasAdminAccount { get; set; }
        public List<string> MemberOf { get; set; } = new();
    }
    
    public class UserListItem
    {
        public string DisplayName { get; set; } = string.Empty;
        public string SamAccountName { get; set; } = string.Empty;
        public string? EmailAddress { get; set; }
        public bool Enabled { get; set; }
        public bool HasAdminAccount { get; set; } // Add this line
    }
}

