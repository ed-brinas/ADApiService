using KeyStone.Models;
using Microsoft.Extensions.Options;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace KeyStone.Services;

/// <summary>
/// Implements the IAdService interface to provide Active Directory user management functionality.
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

    /// <inheritdoc />
    public async Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter, bool? hasAdminAccount)
    {
        return await Task.Run(() =>
        {
            var users = new List<UserListItem>();
            using var domainContext = new PrincipalContext(ContextType.Domain, domain);
            
            foreach (var searchOu in _adSettings.Provisioning.SearchBaseOus)
            {
                using var ouContext = new PrincipalContext(ContextType.Domain, domain, searchOu);
                using var searcher = new PrincipalSearcher(new UserPrincipal(ouContext));
                
                foreach (var result in searcher.FindAll())
                {
                    if (result is UserPrincipal user)
                    {
                        if (!string.IsNullOrEmpty(nameFilter) && !(user.Name?.Contains(nameFilter, StringComparison.OrdinalIgnoreCase) ?? false)) continue;
                        if (statusFilter.HasValue && user.Enabled != statusFilter.Value) continue;

                        var adminExists = CheckIfAdminAccountExists(domainContext, user.SamAccountName);
                        if (hasAdminAccount.HasValue && adminExists != hasAdminAccount.Value) continue;

                        users.Add(new UserListItem
                        {
                            SamAccountName = user.SamAccountName,
                            DisplayName = user.DisplayName,
                            IsEnabled = user.Enabled ?? false,
                            HasAdminAccount = adminExists
                        });
                    }
                }
            }
            return users.OrderBy(u => u.DisplayName);
        });
    }

    /// <inheritdoc />
    public async Task<UserDetailModel?> GetUserDetailsAsync(ClaimsPrincipal callingUser, string domain, string samAccountName)
    {
        return await Task.Run(() =>
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, domain);
                var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, samAccountName);

                if (user == null)
                {
                    _logger.LogWarning("User details requested for non-existent user {SamAccountName} in domain {Domain}", samAccountName, domain);
                    return null;
                }

                using var de = user.GetUnderlyingObject() as DirectoryEntry;
                if (de == null) return null;

                var searcher = new DirectorySearcher(de)
                {
                    PropertiesToLoad = { "extensionAttribute1", "mobile" }
                };
                var result = searcher.FindOne();
                
                var dateOfBirth = result?.Properties["extensionAttribute1"]?.Count > 0 ? result.Properties["extensionAttribute1"][0].ToString() : null;
                var mobileNumber = result?.Properties["mobile"]?.Count > 0 ? result.Properties["mobile"][0].ToString() : null;

                var userDetails = new UserDetailModel
                {
                    SamAccountName = user.SamAccountName,
                    FirstName = user.GivenName,
                    LastName = user.Surname,
                    DisplayName = user.DisplayName,
                    UserPrincipalName = user.UserPrincipalName,
                    EmailAddress = user.EmailAddress,
                    DateOfBirth = dateOfBirth,
                    MobileNumber = mobileNumber,
                    IsEnabled = user.Enabled ?? false,
                    IsLockedOut = user.IsAccountLockedOut(),
                    MemberOf = user.GetGroups().Select(g => g.SamAccountName).ToList(),
                    HasAdminAccount = CheckIfAdminAccountExists(context, samAccountName)
                };

                return userDetails;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user details for {SamAccountName} in domain {Domain}", samAccountName, domain);
                return null;
            }
        });
    }

    /// <inheritdoc />
    public async Task<CreateUserResponse> CreateUserAsync(ClaimsPrincipal callingUser, CreateUserRequest request)
    {
        return await Task.Run(() =>
        {
            var isHighPrivilege = IsUserHighPrivilege(callingUser);
            if (request.CreateAdminAccount && !isHighPrivilege)
            {
                throw new InvalidOperationException("You are not authorized to create privileged accounts.");
            }

            using var context = new PrincipalContext(ContextType.Domain, request.Domain);
            
            using var user = new UserPrincipal(context)
            {
                SamAccountName = request.SamAccountName,
                GivenName = request.FirstName,
                Surname = request.LastName,
                DisplayName = $"{request.FirstName} {request.LastName}",
                UserPrincipalName = $"{request.SamAccountName}@{request.Domain}",
                Enabled = true,
                PasswordNotRequired = false
            };
            
            var initialPassword = GeneratePassword();
            user.SetPassword(initialPassword);
            user.ExpirePasswordNow();
            
            user.Save();

            using (var de = user.GetUnderlyingObject() as DirectoryEntry)
            {
                if (de != null)
                {
                    var ouDn = _adSettings.Provisioning.DefaultUserOuFormat.Replace("{domain-components}", GetDomainComponents(request.Domain));
                    using (var parent = new DirectoryEntry($"LDAP://{request.Domain}/{ouDn}"))
                    {
                        de.MoveTo(parent);
                    }
                    
                    if (!string.IsNullOrEmpty(request.DateOfBirth))
                    {
                        de.Properties["extensionAttribute1"].Value = request.DateOfBirth;
                    }
                    if (!string.IsNullOrEmpty(request.MobileNumber))
                    {
                        de.Properties["mobile"].Value = request.MobileNumber;
                    }
                    de.CommitChanges();
                }
            }
            
            foreach (var groupName in request.OptionalGroups)
            {
                AddUserToGroup(context, user.SamAccountName, groupName);
            }

            var response = new CreateUserResponse
            {
                SamAccountName = user.SamAccountName,
                InitialPassword = initialPassword
            };

            if (request.CreateAdminAccount)
            {
                var adminResponse = CreateAdminAccount(context, request);
                response.AdminAccountName = adminResponse.SamAccountName;
                response.AdminInitialPassword = adminResponse.InitialPassword;
            }

            return response;
        });
    }

    /// <inheritdoc />
    public async Task UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request)
    {
        await Task.Run(() =>
        {
            var isHighPrivilege = IsUserHighPrivilege(callingUser);
            
            using var context = new PrincipalContext(ContextType.Domain, request.Domain);
            var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);
            if (user == null)
            {
                throw new KeyNotFoundException($"User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
            }

            using (var de = user.GetUnderlyingObject() as DirectoryEntry)
            {
                if (de != null)
                {
                    // MODIFIED START // Final fix to prevent DirectoryServicesCOMException by safely clearing attributes. - 2025-09-27 12:08 AM
                    if (request.DateOfBirth != null)
                    {
                        if (string.IsNullOrEmpty(request.DateOfBirth))
                        {
                            if (de.Properties.Contains("extensionAttribute1"))
                            {
                                de.Properties["extensionAttribute1"].Clear();
                            }
                        }
                        else
                        {
                            de.Properties["extensionAttribute1"].Value = request.DateOfBirth;
                        }
                    }
                    if (request.MobileNumber != null)
                    {
                        if (string.IsNullOrEmpty(request.MobileNumber))
                        {
                            if (de.Properties.Contains("mobile"))
                            {
                                de.Properties["mobile"].Clear();
                            }
                        }
                        else
                        {
                            de.Properties["mobile"].Value = request.MobileNumber;
                        }
                    }
                    // MODIFIED END // Final fix to prevent DirectoryServicesCOMException by safely clearing attributes. - 2025-09-27 12:08 AM
                    de.CommitChanges();
                }
            }

            var allOptionalGroups = _adSettings.Provisioning.OptionalGroupsForStandard
                .Concat(_adSettings.Provisioning.OptionalGroupsForHighPrivilege).ToList();
            
            UpdateGroupMembership(context, user, request.OptionalGroups, allOptionalGroups);

            var adminExists = CheckIfAdminAccountExists(context, request.SamAccountName);
            if (isHighPrivilege)
            {
                if (request.HasAdminAccount && !adminExists)
                {
                    var createReq = new CreateUserRequest { SamAccountName = request.SamAccountName, Domain = request.Domain, FirstName = user.GivenName, LastName = user.Surname };
                    CreateAdminAccount(context, createReq);
                }
                else if (!request.HasAdminAccount && adminExists)
                {
                    DisableAdminAccount(context, $"{request.SamAccountName}-a");
                }
            }
        });
    }
    
    /// <inheritdoc />
    public async Task<string> ResetPasswordAsync(UserActionRequest request)
    {
        return await Task.Run(() =>
        {
            using var context = new PrincipalContext(ContextType.Domain, request.Domain);
            var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);
            if (user == null)
            {
                throw new KeyNotFoundException($"User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
            }

            var newPassword = GeneratePassword();
            user.SetPassword(newPassword);
            user.ExpirePasswordNow();
            user.Save();
            
            return newPassword;
        });
    }

    /// <inheritdoc />
    public async Task<string> ResetAdminPasswordAsync(ClaimsPrincipal callingUser, ResetAdminPasswordRequest request)
    {
        return await Task.Run(() =>
        {
            if (!IsUserHighPrivilege(callingUser))
            {
                throw new InvalidOperationException("You are not authorized to reset admin passwords.");
            }

            using var context = new PrincipalContext(ContextType.Domain, request.Domain);
            var adminSam = $"{request.SamAccountName}-a";
            var adminUser = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adminSam);
            if (adminUser == null)
            {
                throw new KeyNotFoundException($"Admin account for '{request.SamAccountName}' not found.");
            }

            var newPassword = GeneratePassword();
            adminUser.SetPassword(newPassword);
            adminUser.ExpirePasswordNow();
            adminUser.Save();
            
            return newPassword;
        });
    }

    /// <inheritdoc />
    public async Task UnlockAccountAsync(UserActionRequest request)
    {
        await Task.Run(() =>
        {
            using var context = new PrincipalContext(ContextType.Domain, request.Domain);
            var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);
            if (user == null)
            {
                throw new KeyNotFoundException($"User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
            }

            if (user.IsAccountLockedOut())
            {
                user.UnlockAccount();
            }
        });
    }

    /// <inheritdoc />
    public async Task DisableAccountAsync(UserActionRequest request)
    {
        await Task.Run(() =>
        {
            using var context = new PrincipalContext(ContextType.Domain, request.Domain);
            var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);
            if (user == null)
            {
                throw new KeyNotFoundException($"User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
            }
            user.Enabled = false;
            user.Save();
        });
    }
    
    /// <inheritdoc />
    public async Task EnableAccountAsync(UserActionRequest request)
    {
        await Task.Run(() =>
        {
            using var context = new PrincipalContext(ContextType.Domain, request.Domain);
            var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, request.SamAccountName);
            if (user == null)
            {
                throw new KeyNotFoundException($"User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
            }
            user.Enabled = true;
            user.Save();
        });
    }


    // --- Private Helper Methods ---

    private bool IsUserHighPrivilege(ClaimsPrincipal callingUser)
    {
        var groupSids = callingUser.FindAll(ClaimTypes.GroupSid).Select(c => c.Value);
        try
        {
            using var context = new PrincipalContext(ContextType.Domain, _adSettings.ForestRootDomain);
            foreach (var sid in groupSids)
            {
                try
                {
                     var group = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, sid);
                     if (group != null && _adSettings.AccessControl.HighPrivilegeGroups.Contains(group.SamAccountName, StringComparer.OrdinalIgnoreCase))
                     {
                         return true;
                     }
                }
                catch (Exception ex)
                {
                    _logger.LogTrace(ex, "Could not resolve SID {Sid} to a group name.", sid);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error connecting to forest root domain '{Domain}' to determine user privilege.", _adSettings.ForestRootDomain);
        }
        return false;
    }

    private bool CheckIfAdminAccountExists(PrincipalContext context, string baseSamAccountName)
    {
        return UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, $"{baseSamAccountName}-a") != null;
    }

    private CreateUserResponse CreateAdminAccount(PrincipalContext context, CreateUserRequest baseRequest)
    {
        var adminSam = $"{baseRequest.SamAccountName}-a";
        
        using var adminUser = new UserPrincipal(context)
        {
            SamAccountName = adminSam,
            DisplayName = $"{baseRequest.FirstName} {baseRequest.LastName} (Admin)",
            UserPrincipalName = $"{adminSam}@{baseRequest.Domain}",
            Enabled = true,
            PasswordNotRequired = false,
        };
        var adminPassword = GeneratePassword();
        adminUser.SetPassword(adminPassword);
        adminUser.ExpirePasswordNow();
        adminUser.Save();

        using (var de = adminUser.GetUnderlyingObject() as DirectoryEntry)
        {
            if (de != null)
            {
                var adminOuDn = _adSettings.Provisioning.AdminUserOuFormat.Replace("{domain-components}", GetDomainComponents(baseRequest.Domain));
                using (var parent = new DirectoryEntry($"LDAP://{baseRequest.Domain}/{adminOuDn}"))
                {
                    de.MoveTo(parent);
                    de.CommitChanges();
                }

                if (baseRequest.PrivilegeGroups.Any())
                {
                    try
                    {
                        var firstPrivilegeGroup = baseRequest.PrivilegeGroups.First();
                        using var groupPrincipal = GroupPrincipal.FindByIdentity(context, firstPrivilegeGroup);
                        if (groupPrincipal != null)
                        {
                            var sidString = groupPrincipal.Sid.ToString();
                            var rid = sidString.Split('-').Last();
                            de.Properties["primaryGroupID"].Value = int.Parse(rid);
                            de.CommitChanges();
                            _logger.LogInformation("Set primary group for {AdminSam} to {GroupName}", adminSam, firstPrivilegeGroup);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to set primary group for admin user {AdminSam}", adminSam);
                    }
                }
            }
        }
        
        foreach (var groupName in baseRequest.PrivilegeGroups)
        {
            AddUserToGroup(context, adminSam, groupName);
        }

        try
        {
            RemoveUserFromGroup(context, adminSam, "Domain Users");
            _logger.LogInformation("Removed {AdminSam} from 'Domain Users' group.", adminSam);
        }
        catch(Exception ex)
        {
            _logger.LogError(ex, "Failed to remove {AdminSam} from 'Domain Users' group.", adminSam);
        }

        return new CreateUserResponse { SamAccountName = adminSam, InitialPassword = adminPassword };
    }

    private void DisableAdminAccount(PrincipalContext context, string adminSam)
    {
        var adminUser = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adminSam);
        if (adminUser != null)
        {
            adminUser.Enabled = false;
            adminUser.Save();
        }
    }

    private void AddUserToGroup(PrincipalContext context, string userName, string groupName)
    {
        try
        {
            using var group = GroupPrincipal.FindByIdentity(context, groupName);
            if (group != null && !group.Members.Contains(context, IdentityType.SamAccountName, userName))
            {
                group.Members.Add(context, IdentityType.SamAccountName, userName);
                group.Save();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add user {UserName} to group {GroupName}", userName, groupName);
        }
    }

    private void RemoveUserFromGroup(PrincipalContext context, string userName, string groupName)
    {
         try
        {
            using var group = GroupPrincipal.FindByIdentity(context, groupName);
            if (group != null && group.Members.Contains(context, IdentityType.SamAccountName, userName))
            {
                group.Members.Remove(context, IdentityType.SamAccountName, userName);
                group.Save();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove user {UserName} from group {GroupName}", userName, groupName);
        }
    }

    private void UpdateGroupMembership(PrincipalContext context, UserPrincipal user, List<string> requestedGroups, List<string> manageableGroups)
    {
        var currentGroups = user.GetGroups()
                                .Where(g => g.SamAccountName != null && manageableGroups.Contains(g.SamAccountName, StringComparer.OrdinalIgnoreCase))
                                .Select(g => g.SamAccountName!)
                                .ToList();

        var groupsToAdd = requestedGroups.Except(currentGroups, StringComparer.OrdinalIgnoreCase).ToList();
        var groupsToRemove = currentGroups.Except(requestedGroups, StringComparer.OrdinalIgnoreCase).ToList();

        foreach (var groupName in groupsToAdd)
        {
            AddUserToGroup(context, user.SamAccountName, groupName);
        }

        foreach (var groupName in groupsToRemove)
        {
            RemoveUserFromGroup(context, user.SamAccountName, groupName);
        }
    }

    private string GetDomainComponents(string domain)
    {
        return "DC=" + domain.Replace(".", ",DC=");
    }

    private string GeneratePassword()
    {
        const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        const string lower = "abcdefghijkmnpqrstuvwxyz";
        const string number = "23456789";
        const string special = "*$-+?_&=!%{}/";
        var random = new Random();
        var res = new StringBuilder();

        res.Append(upper[random.Next(upper.Length)]);
        res.Append(lower[random.Next(lower.Length)]);
        res.Append(number[random.Next(number.Length)]);
        res.Append(special[random.Next(special.Length)]);

        string allChars = upper + lower + number + special;
        for (int i = 0; i < 12; i++)
        {
            res.Append(allChars[random.Next(allChars.Length)]);
        }

        return res.ToString();
    }
}