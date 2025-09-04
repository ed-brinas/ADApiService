namespace ADApiService.Models
{
    /// <summary>
    /// Strongly typed configuration model for all Active Directory settings from appsettings.json.
    /// </summary>
    public class AdSettings
    {
        public string ForestRootDomain { get; set; } = string.Empty;
        public List<DomainSettings> Domains { get; set; } = new();
        public OuSettings OUs { get; set; } = new();
        public GroupSettings Groups { get; set; } = new();
        public RoleSettings Roles { get; set; } = new();
    }

    public class DomainSettings
    {
        public string Name { get; set; } = string.Empty;
        public string DomainController { get; set; } = string.Empty;
    }

    public class OuSettings
    {
        public string DefaultUsers { get; set; } = string.Empty;
        public string AdminUsers { get; set; } = string.Empty;
    }

    public class GroupSettings
    {
        public string DefaultUserGroup { get; set; } = string.Empty;
        public string PrivilegedAdminGroup { get; set; } = string.Empty;
    }

    public class RoleSettings
    {
        public List<string> GeneralAccess { get; set; } = new();
        public List<string> AccountCreation { get; set; } = new();
        public List<string> AssignableGroups { get; set; } = new();
    }
}

