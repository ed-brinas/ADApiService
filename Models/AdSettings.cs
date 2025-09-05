namespace ADApiService.Models
{
    /// <summary>
    /// Maps to the AdSettings section in appsettings.json
    /// </summary>
    public class AdSettings
    {
        public string ForestRootDomain { get; set; } = string.Empty;
        public List<string> Domains { get; set; } = new();
        public AccessControlSettings AccessControl { get; set; } = new();
        public ProvisioningSettings Provisioning { get; set; } = new();
    }

    /// <summary>
    /// Contains settings related to Role-Based Access Control (RBAC).
    /// </summary>
    public class AccessControlSettings
    {
        public List<string> GeneralAccessGroups { get; set; } = new();
        public List<string> HighPrivilegeGroups { get; set; } = new();
    }

    /// <summary>
    /// Contains settings related to the creation and configuration of new user accounts.
    /// </summary>
    public class ProvisioningSettings
    {
        public string DefaultUserOuFormat { get; set; } = "OU=Users,OU=_Managed,DC={domain}";
        public string AdminUserOuFormat { get; set; } = "OU=_AdminAccounts,DC={domain}";
        public List<string> OptionalGroupsForHighPrivilege { get; set; } = new();
        public string AdminGroup { get; set; } = string.Empty;
    }
}

