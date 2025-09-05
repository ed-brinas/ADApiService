using ADApiService.Models;
using Microsoft.Extensions.Options;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;

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

    public async Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter)
    {
        return await Task.Run(() =>
        {
            var users = new List<UserListItem>();
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
                    using var userPrinc = new UserPrincipal(context)
                    {
                        SamAccountName = !string.IsNullOrWhiteSpace(nameFilter) ? $"*{nameFilter}*" : null,
                        Enabled = statusFilter
                    };

                    using var searcher = new PrincipalSearcher(userPrinc);
                    foreach (var result in searcher.FindAll().OfType<UserPrincipal>())
                    {
                        using(result)
                        {
                             var adminSam = $"{result.SamAccountName}-a";
                             // A context for the entire domain is needed to find the admin account which is in a different OU
                             using var domainContext = new PrincipalContext(ContextType.Domain, domain);
                             var hasAdminAccount = UserPrincipal.FindByIdentity(domainContext, IdentityType.SamAccountName, adminSam) != null;

                            users.Add(new UserListItem
                            {
                                DisplayName = result.DisplayName,
                                SamAccountName = result.SamAccountName,
                                EmailAddress = result.EmailAddress,
                                Enabled = result.Enabled ?? false,
                                HasAdminAccount = hasAdminAccount
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error searching for users in OU '{OU}' for domain '{Domain}'.", ou, domain);
                }
            }
            return users.OrderBy(u => u.DisplayName);
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
                var memberOf = user.GetGroups().Select(g => g.SamAccountName).ToList();

                return new UserDetailModel
                {
                    DisplayName = user.DisplayName,
                    SamAccountName = user.SamAccountName,
                    HasAdminAccount = hasAdminAccount,
                    MemberOf = memberOf
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

    public async Task<bool> CreateUserAsync(ClaimsPrincipal callingUser, CreateUserRequest request)
    {
        // Security Check: Only high-privilege users can create admin accounts or assign optional groups.
        if (!IsUserHighPrivilege(callingUser) && (request.CreateAdminAccount || request.OptionalGroups?.Any() == true))
        {
            _logger.LogWarning("SECURITY: User '{User}' without high-privilege rights attempted to create a user with elevated permissions.", callingUser.Identity?.Name);
            return false;
        }

        return await Task.Run(() =>
        {
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
                    PasswordNotRequired = false,
                    UserCannotChangePassword = false,
                    Enabled = true,
                    ExpirePasswordNow = true
                };
                user.SetPassword(request.Password);
                user.Save();

                _logger.LogInformation("Successfully created user '{SamAccountName}'.", request.SamAccountName);

                // Handle optional groups if the creator is privileged
                if (IsUserHighPrivilege(callingUser) && request.OptionalGroups?.Any() == true)
                {
                    AddUserToGroups(context, user, request.OptionalGroups);
                }

                // Handle associated admin account creation
                if (IsUserHighPrivilege(callingUser) && request.CreateAdminAccount)
                {
                    return CreateAssociatedAdminAccount(request);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create user '{SamAccountName}' in domain '{Domain}'.", request.SamAccountName, request.Domain);
                return false;
            }
        });
    }
    
    public async Task<bool> UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request)
    {
        // Security Check: Only high-privilege users can perform updates.
        if (!IsUserHighPrivilege(callingUser))
        {
            _logger.LogWarning("SECURITY: User '{User}' without high-privilege rights attempted to update user '{TargetUser}'.", callingUser.Identity?.Name, request.SamAccountName);
            return false;
        }
        
        return await Task.Run(() =>
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, request.Domain);
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);

                if (user == null)
                {
                    _logger.LogError("Update failed: User '{SamAccountName}' not found in domain '{Domain}'.", request.SamAccountName, request.Domain);
                    return false;
                }
                
                // Manage Optional Groups
                UpdateGroupMembership(context, user, request.OptionalGroups ?? new List<string>());

                // Manage Associated Admin Account
                var adminSam = $"{request.SamAccountName}-a";
                using var adminUser = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adminSam);

                if (request.ManageAdminAccount) // User wants admin account to exist
                {
                    if (adminUser == null)
                    {
                        _logger.LogInformation("Creating missing admin account for '{SamAccountName}'.", request.SamAccountName);
                        // Re-use the creation logic, assuming the user principal has the necessary props.
                        return CreateAssociatedAdminAccount(new CreateUserRequest {
                            Domain = request.Domain,
                            FirstName = user.GivenName,
                            LastName = user.Surname,
                            SamAccountName = user.SamAccountName,
                            Password = GenerateRandomPassword() // Generate a secure random password
                        });
                    }
                }
                else // User wants admin account to NOT exist
                {
                    if (adminUser != null)
                    {
                        _logger.LogInformation("Deleting admin account for '{SamAccountName}'.", request.SamAccountName);
                        adminUser.Delete();
                    }
                }
                
                _logger.LogInformation("Successfully updated user '{SamAccountName}'.", request.SamAccountName);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update user '{SamAccountName}' in domain '{Domain}'.", request.SamAccountName, request.Domain);
                return false;
            }
        });
    }

    #endregion

    #region Password and Account Status

    public async Task<bool> ResetPasswordAsync(ResetPasswordRequest request)
    {
        return await Task.Run(() =>
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, request.Domain);
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);

                if (user == null)
                {
                    _logger.LogError("Password reset failed: User '{SamAccountName}' not found in domain '{Domain}'.", request.SamAccountName, request.Domain);
                    return false;
                }

                user.SetPassword(request.NewPassword);
                user.ExpirePasswordNow = true;
                user.UnlockAccount(); // Resetting password should also unlock
                user.Save();
                _logger.LogInformation("Successfully reset password for user '{SamAccountName}'.", request.SamAccountName);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting password for user '{SamAccountName}'.", request.SamAccountName);
                return false;
            }
        });
    }

    public async Task<bool> UnlockAccountAsync(UserActionRequest request)
    {
        return await Task.Run(() =>
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, request.Domain);
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);

                if (user == null)
                {
                    _logger.LogError("Account unlock failed: User '{SamAccountName}' not found in domain '{Domain}'.", request.SamAccountName, request.Domain);
                    return false;
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
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unlocking account for user '{SamAccountName}'.", request.SamAccountName);
                return false;
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
        var groupSids = user.FindAll(ClaimTypes.GroupSid).Select(c => c.Value);

        try
        {
            using var context = new PrincipalContext(ContextType.Domain, _adSettings.ForestRootDomain);
            foreach (var sid in groupSids)
            {
                try
                {
                    var group = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, sid);
                    if (group?.SamAccountName != null)
                    {
                        groupNames.Add(group.SamAccountName);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogTrace(ex, "Could not resolve SID {Sid} to a group name. This is often normal for built-in SIDs.", sid);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not connect to forest root domain '{Domain}' to resolve group SIDs.", _adSettings.ForestRootDomain);
        }
        return groupNames;
    }

    private bool CreateAssociatedAdminAccount(CreateUserRequest request)
    {
        try
        {
            var adminOu = GetOuForDomain(_adSettings.Provisioning.AdminUserOuFormat, request.Domain);
            using var context = new PrincipalContext(ContextType.Domain, request.Domain, adminOu);
            
            var adminSam = $"{request.SamAccountName}-a";
            var adminDisplayName = $"admin-{request.FirstName}{request.LastName}";
            _logger.LogInformation("Attempting to create admin account '{AdminSam}' in OU '{AdminOu}'.", adminSam, adminOu);

            using var adminUser = new UserPrincipal(context)
            {
                SamAccountName = adminSam,
                DisplayName = adminDisplayName,
                Name = adminDisplayName,
                UserPrincipalName = $"{adminSam}@{request.Domain}",
                PasswordNotRequired = false,
                UserCannotChangePassword = false,
                Enabled = true,
                ExpirePasswordNow = true
            };
            adminUser.SetPassword(GenerateRandomPassword());
            adminUser.Save();

            // Add to the designated admin group
            AddUserToGroups(context, adminUser, [_adSettings.Provisioning.AdminGroup]);
            _logger.LogInformation("Successfully created and configured admin account '{AdminSam}'.", adminSam);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create associated admin account for user '{SamAccountName}'.", request.SamAccountName);
            // This is a critical failure, but we don't roll back the standard user creation.
            // The main operation succeeded, but this part failed.
            return false;
        }
    }
    
    private void AddUserToGroups(PrincipalContext context, UserPrincipal user, List<string> groupNames)
    {
        foreach (var groupName in groupNames.Where(g => !string.IsNullOrWhiteSpace(g)))
        {
            try
            {
                using var group = GroupPrincipal.FindByIdentity(context, IdentityType.SamAccountName, groupName);
                if (group != null)
                {
                    if (!group.Members.Contains(user))
                    {
                        group.Members.Add(user);
                        group.Save();
                        _logger.LogInformation("Added user '{User}' to group '{Group}'.", user.SamAccountName, groupName);
                    }
                }
                else
                {
                    _logger.LogWarning("Could not find group '{Group}' to add user '{User}'.", groupName, user.SamAccountName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to add user '{User}' to group '{Group}'.", user.SamAccountName, groupName);
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

        // Add user to new groups
        var groupsToAdd = targetGroupNames.Except(currentGroupNames, StringComparer.OrdinalIgnoreCase);
        AddUserToGroups(context, user, groupsToAdd.ToList());

        // Remove user from old groups
        var groupsToRemove = currentGroupNames.Except(targetGroupNames, StringComparer.OrdinalIgnoreCase);
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
        // In a real production scenario, use a more robust password generation library
        // that enforces complexity rules dynamically fetched from the domain.
        const string upper = "ABCDEFGHJKLMNOPQRSTUVWXYZ";
        const string lower = "abcdefghijkmnopqrstuvwxyz";
        const string number = "0123456789";
        const string special = "!@#$%^&*?_-";
        var random = new Random();
        var password = new char[14];
        password[0] = upper[random.Next(upper.Length)];
        password[1] = lower[random.Next(lower.Length)];
        password[2] = number[random.Next(number.Length)];
        password[3] = special[random.Next(special.Length)];
        
        var allChars = upper + lower + number + special;
        for (int i = 4; i < password.Length; i++)
        {
            password[i] = allChars[random.Next(allChars.Length)];
        }
        
        return new string(password.OrderBy(x => random.Next()).ToArray());
    }

    #endregion
}

