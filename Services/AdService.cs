using ADApiService.Models;
using Microsoft.Extensions.Options;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using System.Text;

namespace ADApiService.Services;

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
                //user.UnlockAccount();
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

    private AdminAccountDetails CreateAssociatedAdminAccount(CreateUserRequest request, List<string>? groupsToAssign = null)
    {
        var adminOu = GetOuForDomain(_adSettings.Provisioning.AdminUserOuFormat, request.Domain);
        using var context = new PrincipalContext(ContextType.Domain, request.Domain, adminOu);
        
        var adminSam = $"{request.SamAccountName}-a";
        var adminDisplayName = $"admin-{request.FirstName}{request.LastName}";
        var generatedPassword = GenerateRandomPassword();
        _logger.LogInformation("Attempting to create admin account '{AdminSam}' in OU '{AdminOu}'.", adminSam, adminOu);

        using var adminUser = new UserPrincipal(context)
        {
            SamAccountName = adminSam,
            DisplayName = adminDisplayName,
            Name = adminDisplayName,
            UserPrincipalName = $"{adminSam}@{request.Domain}",
            Enabled = true
        };
        adminUser.SetPassword(generatedPassword);
        adminUser.Save();

        _logger.LogDebug("Re-fetching admin user '{AdminSam}' to remove from 'Domain Users'.", adminSam);
        try
        {
            // Reload the user from AD to get the most up-to-date group memberships
            using var savedAdminUser = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adminSam);
            if (savedAdminUser != null)
            {
                using var domainUsersGroup = GroupPrincipal.FindByIdentity(context, "Domain Users");
                if (domainUsersGroup != null && savedAdminUser.IsMemberOf(domainUsersGroup))
                {
                    domainUsersGroup.Members.Remove(savedAdminUser);
                    domainUsersGroup.Save();
                    _logger.LogInformation("Successfully removed admin user '{AdminSam}' from the 'Domain Users' group.", adminSam);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not remove admin user '{AdminSam}' from 'Domain Users' group.", adminSam);
        }

        if (groupsToAssign?.Any() == true)
        {
            AddUserToGroups(adminUser, groupsToAssign, request.Domain);
        }

        _logger.LogInformation("Successfully created and configured admin account '{AdminSam}'.", adminSam);

        return new AdminAccountDetails
        {
            SamAccountName = adminUser.SamAccountName,
            DisplayName = adminUser.DisplayName,
            UserPrincipalName = adminUser.UserPrincipalName,
            InitialPassword = generatedPassword
        };
    }
    
    private void AddUserToGroups(UserPrincipal user, List<string> groupNames, string domain)
    {
        // --- New Primary Group Logic ---
        // Check if there are any optional groups to process
        if (groupNames.Any(g => !string.IsNullOrWhiteSpace(g)))
        {
            var firstGroupName = groupNames.First(g => !string.IsNullOrWhiteSpace(g));
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, domain);
        
                using var primaryGroup = GroupPrincipal.FindByIdentity(context, firstGroupName);
                
                // --- NEW VALIDATION LOGIC ---
                if (primaryGroup == null)
                {
                    _logger.LogWarning("Cannot set primary group. Group '{Group}' not found in domain '{Domain}'.", firstGroupName, domain);
                }
                // GroupType is an enum, so we check for the 'Global' flag. IsSecurityGroup is a boolean.
                else if (primaryGroup.IsSecurityGroup == true && primaryGroup.GroupScope == GroupScope.Global)
                {
                    // --- This is the existing logic, which now only runs if the group is valid ---
                    if (primaryGroup.Sid != null)
                    {
                        var userEntry = (System.DirectoryServices.DirectoryEntry)user.GetUnderlyingObject();
                        var rid = primaryGroup.Sid.Value.Substring(primaryGroup.Sid.Value.LastIndexOf('-') + 1);
                        userEntry.Properties["primaryGroupID"].Value = rid;
                        userEntry.CommitChanges();
                        _logger.LogInformation("Set primary group for user '{User}' to '{Group}' (RID: {Rid}).", user.SamAccountName, firstGroupName, rid);
                        
                        using var domainUsersGroup = GroupPrincipal.FindByIdentity(context, "Domain Users");
                        if (domainUsersGroup != null && user.IsMemberOf(domainUsersGroup))
                        {
                            domainUsersGroup.Members.Remove(user);
                            domainUsersGroup.Save();
                            _logger.LogInformation("Removed user '{User}' from 'Domain Users' as a new primary group was set.", user.SamAccountName);
                        }
                    }
                }
                else
                {
                    // --- Log a warning if the group is not of the correct type ---
                    _logger.LogWarning("Cannot set primary group. Group '{Group}' is not a Global Security Group. Group Scope: {Scope}, Is Security Group: {IsSecurity}.",
                        firstGroupName, primaryGroup.GroupScope, primaryGroup.IsSecurityGroup);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set primary group or remove 'Domain Users' for user '{User}'.", user.SamAccountName);
            }
        }
        // --- End of New Logic ---
    
        // This loop adds the user to ALL selected optional groups, including the primary one.
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
