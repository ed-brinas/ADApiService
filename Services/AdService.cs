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

    public async Task<UserDetailModel?> GetUserDetailsAsync(string domain, string samAccountName)
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

                return new UserDetailModel
                {
                    DisplayName = user.DisplayName,
                    SamAccountName = user.SamAccountName,
                    HasAdminAccount = hasAdminAccount,
                    MemberOf = memberOf!,
                    AccountExpirationDate = user.AccountExpirationDate
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
                    AddUserToGroups(user, request.OptionalGroups);
                    response.GroupsAssociated.AddRange(request.OptionalGroups);
                }

                if (IsUserHighPrivilege(callingUser) && request.CreateAdminAccount)
                {
                    response.AdminAccount = CreateAssociatedAdminAccount(request);
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
                
                user.AccountExpirationDate = request.AccountExpirationDate;
                user.Save();

                UpdateGroupMembership(context, user, request.OptionalGroups ?? new List<string>());

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
                        });
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

    private AdminAccountDetails CreateAssociatedAdminAccount(CreateUserRequest request)
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
        adminUser.ExpirePasswordNow();
        adminUser.Save();

        AddUserToGroups(adminUser, [_adSettings.Provisioning.AdminGroup]);
        _logger.LogInformation("Successfully created and configured admin account '{AdminSam}'.", adminSam);

        return new AdminAccountDetails
        {
            SamAccountName = adminUser.SamAccountName,
            DisplayName = adminUser.DisplayName,
            UserPrincipalName = adminUser.UserPrincipalName,
            InitialPassword = generatedPassword
        };
    }
    
    private void AddUserToGroups(UserPrincipal user, List<string> groupNames)
    {
        foreach (var groupName in groupNames.Where(g => !string.IsNullOrWhiteSpace(g)))
        {
            GroupPrincipal? group = null;
            foreach(var domain in _adSettings.Domains)
            {
                try 
                {
                    using var context = new PrincipalContext(ContextType.Domain, domain);
                    group = GroupPrincipal.FindByIdentity(context, IdentityType.SamAccountName, groupName);
                    if (group != null)
                    {
                        if (!group.Members.Contains(user))
                        {
                            group.Members.Add(user);
                            group.Save();
                            _logger.LogInformation("Added user '{User}' to group '{Group}' found in domain '{Domain}'.", user.SamAccountName, groupName, domain);
                        }
                        break; 
                    }
                }
                catch (Exception ex)
                {
                     _logger.LogError(ex, "Error while trying to add user '{User}' to group '{Group}' in domain '{Domain}'.", user.SamAccountName, groupName, domain);
                }
            }

            if (group == null)
            {
                _logger.LogWarning("Could not find group '{Group}' in any configured domain to add user '{User}'.", groupName, user.SamAccountName);
            }
        }
    }

    private void UpdateGroupMembership(PrincipalContext context, UserPrincipal user, List<string> targetGroupNames)
    {
        var allowedOptionalGroups = _adSettings.Provisioning.OptionalGroupsForHighPrivilege
            .Select(g => g.ToLowerInvariant())
            .ToHashSet();

        var currentGroupNames = user.GetGroups()
            .Select(g => g.SamAccountName)
            .Where(g => g != null && allowedOptionalGroups.Contains(g.ToLowerInvariant()))
            .ToList();

        var groupsToAdd = targetGroupNames.Except(currentGroupNames!, StringComparer.OrdinalIgnoreCase);
        AddUserToGroups(user, groupsToAdd.ToList());

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
        const string upperChars = "ABCDEFGHJKLMNOPQRSTUVWXYZ";
        const string lowerChars = "abcdefghijkmnopqrstuvwxyz";
        const string numberChars = "0123456789";
        const string specialChars = "!@#$%^&*?_-";
        
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

