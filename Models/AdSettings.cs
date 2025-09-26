namespace ADApiService.Models;

/// <summary>
/// Maps to the AdSettings section in appsettings.json, providing strongly-typed access to configuration.
/// </summary>
public class AdSettings
{
    /// <summary>
    /// The DNS name of the root domain in the AD forest (e.g., "contoso.com").
    /// Required for resolving SIDs to names across domains.
    /// </summary>
    public string ForestRootDomain { get; set; } = string.Empty;

    /// <summary>
    /// A list of all domain names the API is authorized to manage (e.g., ["contoso.com", "child.contoso.com"]).
    /// </summary>
    public List<string> Domains { get; set; } = [];

    /// <summary>
    /// Contains settings related to Role-Based Access Control (RBAC).
    /// </summary>
    public AccessControlSettings AccessControl { get; set; } = new();

    /// <summary>
    /// Contains settings related to user account provisioning and searching.
    /// </summary>
    public ProvisioningSettings Provisioning { get; set; } = new();
}

/// <summary>
/// Defines the Active Directory groups that control access to API features.
/// </summary>
public class AccessControlSettings
{
    /// <summary>
    /// A list of AD group names whose members have general access to the portal (list, reset password, unlock).
    /// </summary>
    public List<string> GeneralAccessGroups { get; set; } = [];

    /// <summary>
    /// A list of AD group names whose members have elevated privileges (create users, manage groups, create admin accounts).
    /// </summary>
    public List<string> HighPrivilegeGroups { get; set; } = [];
}

/// <summary>
/// Defines the rules and locations for creating and managing user accounts.
/// </summary>
public class ProvisioningSettings
{
    /// <summary>
    /// A list of specific OU distinguished names where the API is allowed to search for users.
    /// Users in other OUs will be ignored.
    /// </summary>
    public List<string> SearchBaseOus { get; set; } = [];

    /// <summary>
    /// The format string for the distinguished name of the OU where standard user accounts are created.
    /// Use "{domain-components}" as a placeholder for the domain (e.g., "OU=Users,DC={domain-components}").
    /// </summary>
    public string DefaultUserOuFormat { get; set; } = string.Empty;

    /// <summary>
    /// The format string for the distinguished name of the OU where privileged admin accounts (-a accounts) are created.
    /// </summary>
    public string AdminUserOuFormat { get; set; } = string.Empty;

    /// <summary>
    /// A whitelist of AD group names that high-privilege users are allowed to assign to other users.
    /// </summary>
    public List<string> OptionalGroupsForHighPrivilege { get; set; } = [];

    /// <summary>
    /// The name of the AD group to which newly created associated admin accounts (-a accounts) are added.
    /// </summary>
    public string AdminGroup { get; set; } = string.Empty;
}

