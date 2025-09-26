using KeyStone.Models;
using Microsoft.Extensions.Options;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using System.Text;

// Added
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
// using Microsoft.Extensions.Logging; // if needed

namespace KeyStone.Services;

/// <summary>
/// Service implementation for interacting with Active Directory.
/// </summary>
public class AdService : IAdService
{
    private readonly AdSettings _adSettings;
    private readonly ILogger<AdService> _logger;

    public AdService(IOptions<AdSettings> adSettings, ILogger<AdService> logger)
    {
        _adSettings = adSettings.Value;
        _logger = logger;
    }

    #region User Listing and Details

    public async Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter, bool? hasAdminAccountFilter)
    {
        return await Task.Run(() =>
        {
            var userDictionary = new Dictionary<string, UserListItem>();
            var domainDc = $"DC={domain.Replace(".", ",DC=")}";

            var relevantOus = _adSettings.Provisioning.SearchBaseOus
                .Where(ou => ou.EndsWith(domainDc, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (!relevantOus.Any())
            {
                _logger.LogWarning("No SearchBaseOus configured for domain '{Domain}'. No users will be listed.", domain);
                return Enumerable.Empty<UserListItem>();
            }

            foreach (var ou in relevantOus)
            {
                try
                {
                    using var context = new PrincipalContext(ContextType.Domain, domain, ou);
                    
                    var searchPrincipals = new List<UserPrincipal>();
                    if (!string.IsNullOrWhiteSpace(nameFilter))
                    {
                        // Add principals for each attribute to search
                        searchPrincipals.Add(new UserPrincipal(context) { SamAccountName = $"*{nameFilter}*" });
                        searchPrincipals.Add(new UserPrincipal(context) { DisplayName = $"*{nameFilter}*" });
                        searchPrincipals.Add(new UserPrincipal(context) { EmailAddress = $"*{nameFilter}*" });
                    }
                    else
                    {
                        searchPrincipals.Add(new UserPrincipal(context)); // Empty filter for all users
                    }

                    foreach(var userPrinc in searchPrincipals)
                    {
                        if (statusFilter.HasValue)
                        {
                            userPrinc.Enabled = statusFilter;
                        }

                        using var searcher = new PrincipalSearcher(userPrinc);
                        foreach (var result in searcher.FindAll().OfType<UserPrincipal>())
                        {
                            using(result)
                            {
                                if (result.SamAccountName != null && !userDictionary.ContainsKey(result.SamAccountName))
                                {
                                    var adminSam = $"{result.SamAccountName}-a";
                                    using var domainContext = new PrincipalContext(ContextType.Domain, domain);
                                    var hasAdminAccount = UserPrincipal.FindByIdentity(domainContext, IdentityType.SamAccountName, adminSam) != null;

                                    userDictionary[result.SamAccountName] = new UserListItem
                                    {
                                        DisplayName = result.DisplayName,
                                        SamAccountName = result.SamAccountName,
                                        EmailAddress = result.EmailAddress,
                                        Enabled = result.Enabled ?? false,
                                        HasAdminAccount = hasAdminAccount,
                                        AccountExpirationDate = result.AccountExpirationDate
                                    };
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error searching for users in OU '{OU}' for domain '{Domain}'.", ou, domain);
                }
            }

            IEnumerable<UserListItem> finalUsers = userDictionary.Values;
            if (hasAdminAccountFilter.HasValue)
            {
                finalUsers = finalUsers.Where(u => u.HasAdminAccount == hasAdminAccountFilter.Value);
            }

            return finalUsers.OrderBy(u => u.DisplayName);
        });
    }

    public async Task<UserDetailModel?> GetUserDetailsAsync(ClaimsPrincipal callingUser, string domain, string samAccountName)
    {
        return await Task.Run(() =>
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, domain);
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, samAccountName);

                if (user == null)
                {
                    _logger.LogWarning("User details requested for non-existent user '{SamAccountName}' in domain '{Domain}'.", samAccountName, domain);
                    return null;
                }
                
                var adminSam = $"{user.SamAccountName}-a";
                var hasAdminAccount = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adminSam) != null;
                var memberOf = user.GetGroups().Select(g => g.SamAccountName).Where(s => s != null).ToList();

                // New logic for the feature flag
                var canReset = IsUserHighPrivilege(callingUser) && hasAdminAccount;

                return new UserDetailModel
                {
                    DisplayName = user.DisplayName,
                    SamAccountName = user.SamAccountName,
                    FirstName = user.GivenName,
                    LastName = user.Surname,
                    HasAdminAccount = hasAdminAccount,
                    MemberOf = memberOf!,
                    AccountExpirationDate = user.AccountExpirationDate,
                    CanAutoResetPassword = canReset
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting details for user '{SamAccountName}' in domain '{Domain}'.", samAccountName, domain);
                return null;
            }
        });
    }

    #endregion

    #region User Creation and Updates

    public async Task<CreateUserResponse> CreateUserAsync(ClaimsPrincipal callingUser, CreateUserRequest request)
    {
        if (!IsUserHighPrivilege(callingUser) && (request.CreateAdminAccount || request.OptionalGroups?.Any() == true))
        {
            _logger.LogWarning("SECURITY: User '{User}' attempted to create user with elevated permissions.", callingUser.Identity?.Name);
            throw new InvalidOperationException("You do not have permission to create users with optional groups or associated admin accounts.");
        }

        return await Task.Run(() =>
        {
            var response = new CreateUserResponse();
            var generatedPassword = GenerateRandomPassword();

            try
            {
                var ou = GetOuForDomain(_adSettings.Provisioning.DefaultUserOuFormat, request.Domain);
                using var context = new PrincipalContext(ContextType.Domain, request.Domain, ou);
                
                _logger.LogInformation("Attempting to create user '{SamAccountName}' in OU '{OU}'.", request.SamAccountName, ou);
                
                using var user = new UserPrincipal(context)
                {
                    SamAccountName = request.SamAccountName,
                    GivenName = request.FirstName,
                    Surname = request.LastName,
                    DisplayName = $"{request.FirstName} {request.LastName}",
                    Name = $"{request.FirstName} {request.LastName}",
                    UserPrincipalName = $"{request.SamAccountName}@{request.Domain}",
                    PasswordNotRequired = false,
                    UserCannotChangePassword = false,
                    Enabled = true,
                    AccountExpirationDate = request.AccountExpirationDate
                };
                user.SetPassword(generatedPassword);
                user.Save();
                user.ExpirePasswordNow();
                user.Save();
                
                response.UserAccount = new UserAccountDetails
                {
                    SamAccountName = user.SamAccountName,
                    DisplayName = user.DisplayName,
                    UserPrincipalName = user.UserPrincipalName,
                    InitialPassword = generatedPassword
                };

                if (IsUserHighPrivilege(callingUser) && request.OptionalGroups?.Any() == true)
                {
                    AddUserToGroups(user, request.OptionalGroups, request.Domain);
                    response.GroupsAssociated.AddRange(request.OptionalGroups);
                }

                if (IsUserHighPrivilege(callingUser) && request.CreateAdminAccount)
                {
                    response.AdminAccount = CreateAssociatedAdminAccount(request, request.OptionalGroups);
                }
                
                response.Message = $"Successfully created user '{request.SamAccountName}'.";
                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AD ERROR on CreateUserAsync for '{SamAccountName}'.", request.SamAccountName);
                throw; 
            }
        });
    }
    
    public async Task UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request)
    {
        if (!IsUserHighPrivilege(callingUser))
        {
            _logger.LogWarning("SECURITY: User '{User}' without high-privilege rights attempted to update user '{TargetUser}'.", callingUser.Identity?.Name, request.SamAccountName);
            throw new InvalidOperationException("You do not have permission to update user group memberships or manage admin accounts.");
        }
        
        await Task.Run(() =>
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, request.Domain);
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);

                if (user == null)
                {
                    throw new KeyNotFoundException($"Update failed: User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
                }
                
                user.GivenName = request.FirstName;
                user.Surname = request.LastName;
                user.DisplayName = $"{request.FirstName} {request.LastName}";
                user.AccountExpirationDate = request.AccountExpirationDate;
                user.Save();

                UpdateGroupMembership(context, user, request.OptionalGroups ?? new List<string>(), request.Domain);

                var adminSam = $"{request.SamAccountName}-a";
                using var adminUser = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adminSam);

                if (request.ManageAdminAccount)
                {
                    if (adminUser == null)
                    {
                        _logger.LogInformation("Creating missing admin account for '{SamAccountName}'.", request.SamAccountName);
                        CreateAssociatedAdminAccount(new CreateUserRequest {
                            Domain = request.Domain,
                            FirstName = user.GivenName ?? "Admin",
                            LastName = user.Surname ?? user.SamAccountName,
                            SamAccountName = user.SamAccountName,
                            AccountExpirationDate = request.AccountExpirationDate 
                        }, request.OptionalGroups);
                    }
                }
                else
                {
                    if (adminUser != null)
                    {
                        _logger.LogInformation("Deleting admin account for '{SamAccountName}'.", request.SamAccountName);
                        adminUser.Delete();
                    }
                }
                
                _logger.LogInformation("Successfully updated user '{SamAccountName}'.", request.SamAccountName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AD ERROR on UpdateUserAsync for '{SamAccountName}'.", request.SamAccountName);
                throw;
            }
        });
    }

    #endregion

    #region Password and Account Status

    public async Task<string> ResetPasswordAsync(UserActionRequest request)
    {
        return await Task.Run(() =>
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, request.Domain);
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);

                if (user == null)
                {
                    throw new KeyNotFoundException($"Password reset failed: User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
                }

                var newPassword = GenerateRandomPassword();
                user.SetPassword(newPassword);
                user.ExpirePasswordNow();
                user.UnlockAccount();
                user.Save();
                _logger.LogInformation("Successfully reset password for user '{SamAccountName}'.", request.SamAccountName);
                return newPassword;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AD ERROR on ResetPasswordAsync for '{SamAccountName}'.", request.SamAccountName);
                throw;
            }
        });
    }

    public async Task<string> ResetAdminPasswordAsync(ClaimsPrincipal callingUser, ResetAdminPasswordRequest request)
    {
        if (!IsUserHighPrivilege(callingUser))
        {
            _logger.LogWarning("SECURITY: User '{User}' without high-privilege rights attempted to reset an admin password for '{TargetUser}'.", callingUser.Identity?.Name, request.SamAccountName);
            throw new InvalidOperationException("You do not have permission to perform this action.");
        }

        return await Task.Run(() =>
        {
            try
            {
                var adminOu = GetOuForDomain(_adSettings.Provisioning.AdminUserOuFormat, request.Domain);
                using var context = new PrincipalContext(ContextType.Domain, request.Domain, adminOu);
                
                var adminSam = $"{request.SamAccountName}-a";
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adminSam);

                if (user == null)
                {
                    throw new KeyNotFoundException($"Admin account reset failed: User '{adminSam}' not found in the admin OU for domain '{request.Domain}'. The account may exist in a different OU or not at all.");
                }

                var newPassword = GenerateRandomPassword();
                user.SetPassword(newPassword);
                user.UnlockAccount();
                user.AccountExpirationDate = DateTime.UtcNow.AddDays(30);
                user.Save();
                                
                _logger.LogInformation("Successfully reset password for admin account '{AdminSam}'.", adminSam);
                return newPassword;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AD ERROR on ResetAdminPasswordAsync for '{SamAccountName}'.", request.SamAccountName);
                throw;
            }
        });
    }

    public async Task UnlockAccountAsync(UserActionRequest request)
    {
        await Task.Run(() =>
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, request.Domain);
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);

                if (user == null)
                {
                    throw new KeyNotFoundException($"Account unlock failed: User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
                }
                
                if(user.IsAccountLockedOut())
                {
                    user.UnlockAccount();
                    user.Save();
                    _logger.LogInformation("Successfully unlocked account for user '{SamAccountName}'.", request.SamAccountName);
                }
                else
                {
                    _logger.LogInformation("Account for user '{SamAccountName}' was not locked.", request.SamAccountName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AD ERROR on UnlockAccountAsync for '{SamAccountName}'.", request.SamAccountName);
                throw;
            }
        });
    }

    public async Task DisableAccountAsync(UserActionRequest request)
    {
        await Task.Run(() =>
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, request.Domain);
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);

                if (user == null)
                {
                    throw new KeyNotFoundException($"Account disable failed: User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
                }

                if (user.Enabled == true)
                {
                    user.Enabled = false;
                    user.Save();
                    _logger.LogInformation("Successfully disabled account for user '{SamAccountName}'.", request.SamAccountName);
                }
                else
                {
                    _logger.LogInformation("Account for user '{SamAccountName}' was already disabled.", request.SamAccountName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AD ERROR on DisableAccountAsync for '{SamAccountName}'.", request.SamAccountName);
                throw;
            }
        });
    }
    
    public async Task EnableAccountAsync(UserActionRequest request)
    {
        await Task.Run(() =>
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, request.Domain);
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);

                if (user == null)
                {
                    throw new KeyNotFoundException($"Account enable failed: User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
                }

                if (user.Enabled == false)
                {
                    user.Enabled = true;
                    user.Save();
                    _logger.LogInformation("Successfully enabled account for user '{SamAccountName}'.", request.SamAccountName);
                }
                else
                {
                    _logger.LogInformation("Account for user '{SamAccountName}' was already enabled.", request.SamAccountName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AD ERROR on EnableAccountAsync for '{SamAccountName}'.", request.SamAccountName);
                throw;
            }
        });
    }

    #endregion

    #region Helper Methods
    
    private bool IsUserHighPrivilege(ClaimsPrincipal callingUser)
    {
        var userGroups = GetUserGroupNames(callingUser);
        return _adSettings.AccessControl.HighPrivilegeGroups.Any(g => userGroups.Contains(g, StringComparer.OrdinalIgnoreCase));
    }

    private List<string> GetUserGroupNames(ClaimsPrincipal user)
    {
        var groupNames = new List<string>();
        var groupSids = user.FindAll(ClaimTypes.GroupSid).Select(c => c.Value).ToList();
        var unresolvedSids = new HashSet<string>(groupSids);

        foreach (var domain in _adSettings.Domains)
        {
            if (!unresolvedSids.Any()) break;

            try
            {
                using var context = new PrincipalContext(ContextType.Domain, domain);
                var sidsInThisDomain = unresolvedSids.ToList();

                foreach (var sid in sidsInThisDomain)
                {
                    try
                    {
                        var group = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, sid);
                        if (group?.SamAccountName != null)
                        {
                            groupNames.Add(group.SamAccountName);
                            unresolvedSids.Remove(sid);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogTrace(ex, "Could not resolve SID {Sid} in domain {Domain}. This is expected if the group belongs to another domain.", sid, domain);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not connect to PrincipalContext for domain '{Domain}' while resolving groups in AdService.", domain);
            }
        }
        return groupNames;
    }
//
// REPLACE the entire CreateAssociatedAdminAccount method with this version
public AdminAccountDetails CreateAssociatedAdminAccount(CreateUserRequest request, List<string>? groupsToAssign = null)
{
    var adminOu = GetOuForDomain(_adSettings.Provisioning.AdminUserOuFormat, request.Domain);
    var adminSam = SafeSam($"{request.SamAccountName}-a");
    var adminDisplayName = $"admin-{request.FirstName}{request.LastName}".ToLower(CultureInfo.InvariantCulture);
    var userPrincipalName = $"{adminSam}@{request.Domain}";
    var generatedPassword = GenerateRandomPassword();
    var normalizedGroups = NormalizeGroups(groupsToAssign);

    _logger.LogInformation("Attempting to create admin account '{AdminSam}' in OU '{AdminOu}'.", adminSam, adminOu);

    // Keep both contexts alive during the operation:
    using var ouCtx     = new PrincipalContext(ContextType.Domain, request.Domain, adminOu);
    using var domainCtx = new PrincipalContext(ContextType.Domain, request.Domain);

    using var adminUser = new UserPrincipal(ouCtx)
    {
        SamAccountName        = adminSam,
        Name                  = adminDisplayName,
        DisplayName           = adminDisplayName,
        UserPrincipalName     = userPrincipalName,
        Enabled               = false,
        AccountExpirationDate = DateTime.UtcNow.AddDays(30),
    };

    try
    {
        adminUser.Save();
        _logger.LogInformation("Initial save for admin account '{AdminSam}' complete.", adminSam);

        adminUser.SetPassword(generatedPassword);
        adminUser.Enabled = true;
        adminUser.Save();
        _logger.LogInformation("Password set and account enabled for '{AdminSam}'.", adminSam);
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Failed creating/enabling admin account '{AdminSam}'.", adminSam);
        throw;
    }

    // Add to all requested groups (use context-safe helpers)
    if (normalizedGroups.Count > 0)
    {
        foreach (var groupName in normalizedGroups)
        {
            try
            {
                using var grp = ResolveGroupWithAliveContext(domainCtx, groupName)
                             ?? ResolveGroupForestWide(groupName);
                if (grp == null)
                {
                    _logger.LogWarning("Group '{Group}' not found (forest-wide). Skipping for '{AdminSam}'.", groupName, adminSam);
                    continue;
                }

                // Rebind user by DN into the same context as the group to avoid cross-context issues
                using var userByDn = UserPrincipal.FindByIdentity(grp.Context ?? domainCtx, IdentityType.DistinguishedName, adminUser.DistinguishedName);
                if (userByDn == null)
                {
                    _logger.LogError("Could not bind user '{AdminSam}' by DN to add to '{Group}'.", adminSam, grp.SamAccountName ?? grp.Name);
                    continue;
                }

                var added = TryAddMember(grp, userByDn, adminSam);
                if (!added)
                    _logger.LogDebug("'{AdminSam}' is already a member of '{Group}'.", adminSam, grp.SamAccountName ?? grp.Name);
                else
                    _logger.LogInformation("Added '{AdminSam}' to group '{Group}'.", adminSam, grp.SamAccountName ?? grp.Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to add '{AdminSam}' to group '{Group}'. Continuing.", adminSam, groupName);
            }
        }
    }

    // Set primary group last, then remove Domain Users
    var candidatePrimary = normalizedGroups.FirstOrDefault();
    if (!string.IsNullOrWhiteSpace(candidatePrimary))
    {
        TrySetPrimaryGroupWithRetries(domainCtx, adminUser, adminSam, candidatePrimary);

        try
        {
            using var domainUsers = ResolveGroupWithAliveContext(domainCtx, "Domain Users");
            if (domainUsers != null)
            {
                using var userByDn = UserPrincipal.FindByIdentity(domainCtx, IdentityType.DistinguishedName, adminUser.DistinguishedName);
                if (userByDn != null && IsMemberOfSameContext(domainUsers, userByDn))
                {
                    domainUsers.Members.Remove(userByDn);
                    domainUsers.Save();
                    _logger.LogInformation("Removed '{AdminSam}' from 'Domain Users'.", adminSam);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed removing '{AdminSam}' from 'Domain Users' (non-fatal).", adminSam);
        }
    }
    else
    {
        _logger.LogInformation("No groups provided to set as primary for '{AdminSam}'. Skipping primary group step.", adminSam);
    }

    _logger.LogInformation("Successfully created and configured admin account '{AdminSam}'.", adminSam);

    return new AdminAccountDetails
    {
        SamAccountName    = adminSam,
        DisplayName       = adminDisplayName,
        UserPrincipalName = userPrincipalName,
        InitialPassword   = generatedPassword
    };
}

// REPLACE your current TrySetPrimaryGroupWithRetries with this version (note the signature change)
private void TrySetPrimaryGroupWithRetries(
    PrincipalContext domainCtx,
    UserPrincipal adminUser,
    string adminSam,
    string primaryGroupName)
{
    if (primaryGroupName.Equals("Domain Users", StringComparison.OrdinalIgnoreCase))
    {
        _logger.LogWarning("'{AdminSam}': Requested primary group is 'Domain Users'. Skipping explicit primary change.", adminSam);
        return;
    }

    using var primaryGroup = ResolveGroupWithAliveContext(domainCtx, primaryGroupName)
                          ?? ResolveGroupForestWide(primaryGroupName);
    if (primaryGroup == null)
    {
        _logger.LogWarning("'{AdminSam}': Primary group '{Group}' not found.", adminSam, primaryGroupName);
        return;
    }
    if (primaryGroup.IsSecurityGroup != true || primaryGroup.GroupScope != GroupScope.Global)
    {
        _logger.LogWarning("'{AdminSam}': Group '{Group}' is not a Global Security Group. Skipping primary group set.", adminSam, primaryGroupName);
        return;
    }

    using var userByDn = UserPrincipal.FindByIdentity(domainCtx, IdentityType.DistinguishedName, adminUser.DistinguishedName);
    if (userByDn == null)
    {
        _logger.LogError("'{AdminSam}': Could not rebind user by DN in domain context for primary group.", adminSam);
        return;
    }

    if (!IsMemberOfSameContext(primaryGroup, userByDn))
    {
        var added = TryAddMember(primaryGroup, userByDn, adminSam);
        if (!added)
        {
            _logger.LogWarning("'{AdminSam}': Not a member of '{Group}' and could not add. Skipping primary group set.", adminSam, primaryGroupName);
            return;
        }
    }

    const int maxAttempts = 4;
    var delayMs = 600;

    for (var attempt = 1; attempt <= maxAttempts; attempt++)
    {
        try
        {
            using var userEntry = (DirectoryEntry)userByDn.GetUnderlyingObject(); // fresh each attempt
            var rid = GetRidFromSid(primaryGroup.Sid);
            userEntry.Properties["primaryGroupID"].Value = rid;
            userEntry.CommitChanges();

            _logger.LogInformation("Successfully set primary group for '{AdminSam}' to '{Group}'.", adminSam, primaryGroupName);
            return;
        }
        catch (DirectoryServicesCOMException comEx)
        {
            if (attempt >= maxAttempts)
            {
                _logger.LogError(comEx, "Failed to set primary group for '{AdminSam}' to '{Group}' after {Attempts} attempts.", adminSam, primaryGroupName, attempt);
                return;
            }
            _logger.LogWarning(comEx, "Attempt {Attempt}/{Max} to set primary group for '{AdminSam}' failed. Retrying in {DelayMs} ms.", attempt, maxAttempts, adminSam, delayMs);
        }
        catch (ObjectDisposedException ode)
        {
            if (attempt >= maxAttempts)
            {
                _logger.LogError(ode, "Failed to set primary group for '{AdminSam}' to '{Group}' after {Attempts} attempts (disposed).", adminSam, primaryGroupName, attempt);
                return;
            }
            _logger.LogWarning(ode, "Attempt {Attempt}/{Max} to set primary group for '{AdminSam}' failed due to disposed object. Retrying in {DelayMs} ms.", attempt, maxAttempts, adminSam, delayMs);
        }

        Thread.Sleep(delayMs);
        delayMs *= 2;
    }
}

// ADD these helpers (do not remove your existing ones if already present)

private static GroupPrincipal? ResolveGroupWithAliveContext(PrincipalContext aliveDomainCtx, string rawInput)
{
    var token = rawInput?.Trim();
    if (string.IsNullOrWhiteSpace(token)) return null;

    return  TryFindGroup(aliveDomainCtx, IdentityType.DistinguishedName, token) ??
            TryFindGroup(aliveDomainCtx, IdentityType.Sid,              token) ??
            TryFindGroup(aliveDomainCtx, IdentityType.Guid,             token) ??
            TryFindGroup(aliveDomainCtx, IdentityType.SamAccountName,   token) ??
            TryFindGroup(aliveDomainCtx, IdentityType.Name,             token);
}

private static GroupPrincipal? ResolveGroupForestWide(string rawInput)
{
    var dn = TryFindGroupDnViaGlobalCatalog(rawInput?.Trim() ?? string.Empty);
    if (dn == null) return null;

    var fqdn = ExtractDomainFromDn(dn);
    var ctx  = new PrincipalContext(ContextType.Domain, fqdn); // intentionally not disposed here; disposed by GroupPrincipal
    return TryFindGroup(ctx, IdentityType.DistinguishedName, dn);
}

private static GroupPrincipal? TryFindGroup(PrincipalContext ctx, IdentityType type, string value)
{
    try { return GroupPrincipal.FindByIdentity(ctx, type, value); }
    catch { return null; }
}

private static bool TryAddMember(GroupPrincipal group, Principal userInSameContext, string adminSamForLog)
{
    try
    {
        if (IsMemberOfSameContext(group, userInSameContext))
            return false;

        group.Members.Add(userInSameContext);
        group.Save();
        return true;
    }
    catch (PrincipalOperationException poe) when (poe.Message.IndexOf("already", StringComparison.OrdinalIgnoreCase) >= 0)
    {
        return false;
    }
}

private static bool IsMemberOfSameContext(GroupPrincipal group, Principal userInSameContext)
{
    try { return userInSameContext.IsMemberOf(group); }
    catch { return false; }
}

private static string? TryFindGroupDnViaGlobalCatalog(string nameOrSam)
{
    if (string.IsNullOrWhiteSpace(nameOrSam)) return null;
    try
    {
        using var gcRoot = new DirectoryEntry("GC://");
        using var ds = new DirectorySearcher(gcRoot)
        {
            SearchScope = SearchScope.Subtree,
            Filter = $"(&(objectClass=group)(|(cn={EscapeLdap(nameOrSam)})(name={EscapeLdap(nameOrSam)})(sAMAccountName={EscapeLdap(nameOrSam)})))",
            PageSize = 200
        };
        var res = ds.FindOne();
        return res?.Properties["distinguishedName"]?.Count > 0
            ? res.Properties["distinguishedName"][0]?.ToString()
            : null;
    }
    catch { return null; }
}

private static string ExtractDomainFromDn(string dn)
{
    var m = Regex.Matches(dn, @"DC=([^,]+)", RegexOptions.IgnoreCase);
    return string.Join(".", m.Select(x => x.Groups[1].Value));
}

private static string EscapeLdap(string value)
{
    return value
        .Replace(@"\", @"\5c")
        .Replace("*",  @"\2a")
        .Replace("(",  @"\28")
        .Replace(")",  @"\29")
        .Replace("\0", @"\00");
}

// Ensures sAMAccountName meets legacy 20-char limit and isn't empty
private static string SafeSam(string proposed)
{
    const int maxLen = 20;
    var t = (proposed ?? string.Empty).Trim();
    if (t.Length > maxLen) t = t[..maxLen];
    if (string.IsNullOrWhiteSpace(t))
        throw new ArgumentException("Proposed sAMAccountName is empty after normalization.");
    return t;
}
// Trim, de-dupe (case-insensitive), and drop blanks from group list
private static IReadOnlyList<string> NormalizeGroups(IEnumerable<string>? groups)
{
    if (groups == null) return Array.Empty<string>();
    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var result = new List<string>();
    foreach (var g in groups)
    {
        var trimmed = g?.Trim();
        if (string.IsNullOrWhiteSpace(trimmed)) continue;
        if (seen.Add(trimmed)) result.Add(trimmed);
    }
    return result;
}
// Extract the RID (last sub-authority) from a SID; needed for primaryGroupID
private static int GetRidFromSid(System.Security.Principal.SecurityIdentifier sid)
{
    var parts = sid.Value.Split('-');
    var last = parts[^1];
    if (!int.TryParse(last, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var rid))
        throw new InvalidOperationException($"Invalid SID format: {sid.Value}");
    return rid;
}

//   
    private void AddUserToGroups(UserPrincipal user, List<string> groupNames, string domain)
    {
        foreach (var groupName in groupNames.Where(g => !string.IsNullOrWhiteSpace(g)))
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, domain);
                using var group = GroupPrincipal.FindByIdentity(context, IdentityType.SamAccountName, groupName);
                
                if (group != null)
                {
                    if (!group.Members.Contains(user))
                    {
                        group.Members.Add(user);
                        group.Save();
                        _logger.LogInformation("Added user '{User}' to group '{Group}' in domain '{Domain}'.", user.SamAccountName, groupName, domain);
                    }
                }
                else
                {
                    _logger.LogWarning("Could not find group '{Group}' in domain '{Domain}' to add user '{User}'.", groupName, domain, user.SamAccountName);
                }
            }
            catch (Exception ex)
            {
                 _logger.LogError(ex, "Error while trying to add user '{User}' to group '{Group}' in domain '{Domain}'.", user.SamAccountName, groupName, domain);
            }
        }
    }

    private void UpdateGroupMembership(PrincipalContext context, UserPrincipal user, List<string> targetGroupNames, string domain)
    {
        var allowedOptionalGroups = _adSettings.Provisioning.OptionalGroupsForHighPrivilege
            .Select(g => g.ToLowerInvariant())
            .ToHashSet();

        var currentGroupNames = user.GetGroups()
            .Select(g => g.SamAccountName)
            .Where(g => g != null && allowedOptionalGroups.Contains(g.ToLowerInvariant()))
            .ToList();

        var groupsToAdd = targetGroupNames.Except(currentGroupNames!, StringComparer.OrdinalIgnoreCase);
        AddUserToGroups(user, groupsToAdd.ToList(), domain);

        var groupsToRemove = currentGroupNames!.Except(targetGroupNames, StringComparer.OrdinalIgnoreCase);
        foreach (var groupName in groupsToRemove)
        {
             try
            {
                using var group = GroupPrincipal.FindByIdentity(context, IdentityType.SamAccountName, groupName);
                if (group != null && group.Members.Contains(user))
                {
                    group.Members.Remove(user);
                    group.Save();
                    _logger.LogInformation("Removed user '{User}' from group '{Group}'.", user.SamAccountName, groupName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove user '{User}' from group '{Group}'.", user.SamAccountName, groupName);
            }
        }
    }
    
    private string GetOuForDomain(string ouFormat, string domain)
    {
        var domainComponents = $"DC={domain.Replace(".", ",DC=")}";
        return ouFormat.Replace("{domain-components}", domainComponents, StringComparison.OrdinalIgnoreCase);
    }
    
    private string GenerateRandomPassword()
    {
        const string upperChars = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        const string lowerChars = "abcdefghijkmnpqrstuvwxyz";
        const string numberChars = "123456789";
        const string specialChars = "!$&@!$&@";
        
        var random = new Random();
        var passwordChars = new List<char>();

        for (int i = 0; i < 3; i++) { passwordChars.Add(upperChars[random.Next(upperChars.Length)]); }
        for (int i = 0; i < 3; i++) { passwordChars.Add(numberChars[random.Next(numberChars.Length)]); }
        for (int i = 0; i < 2; i++) { passwordChars.Add(specialChars[random.Next(specialChars.Length)]); }
        for (int i = 0; i < 2; i++) { passwordChars.Add(lowerChars[random.Next(lowerChars.Length)]); }

        var shuffledPassword = new string(passwordChars.OrderBy(x => random.Next()).ToArray());
        _logger.LogDebug("Generated new random password of length {Length}", shuffledPassword.Length);
        return shuffledPassword;
    }

    #endregion
}
