namespace KeyStone.Models;

public class AdSettings
{
    public string ForestRootDomain { get; set; } = string.Empty;
    public List<string> Domains { get; set; } = new();
    public AccessControlSettings AccessControl { get; set; } = new();
    public ProvisioningSettings Provisioning { get; set; } = new();
}

public class AccessControlSettings
{
    public List<string> GeneralAccessGroups { get; set; } = new();
    public List<string> HighPrivilegeGroups { get; set; } = new();
}

public class ProvisioningSettings
{
    public string DefaultUserOuFormat { get; set; } = string.Empty;
    public string AdminUserOuFormat { get; set; } = string.Empty;
    public List<string> OptionalGroupsForStandard { get; set; } = new(); // Renamed from OptionalGroupsForGeneralAccess
    public List<string> OptionalGroupsForHighPrivilege { get; set; } = new();
    public string AdminGroup { get; set; } = string.Empty;
    public List<string> SearchBaseOus { get; set; } = new();
}