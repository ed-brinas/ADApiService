namespace ADApiService.Models;

public class AdSettings
{
    public string ForestRootDomain { get; set; } = string.Empty;
    public List<string> Domains { get; set; } = [];
    public string DefaultUserOuFormat { get; set; } = string.Empty;
    public string AdminUserOuFormat { get; set; } = string.Empty;
    public AccessControlSettings AccessControl { get; set; } = new();
    public ProvisioningSettings Provisioning { get; set; } = new();
}

public class AccessControlSettings
{
    public List<string> GeneralAccessGroups { get; set; } = [];
    public List<string> HighPrivilegeGroups { get; set; } = [];
}

public class ProvisioningSettings
{
    public List<string> DefaultUserGroups { get; set; } = [];
    public List<string> OptionalUserGroups { get; set; } = [];
    public List<string> DefaultAdminGroups { get; set; } = [];
}
