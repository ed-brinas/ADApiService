using ADApiService.Models;
using Microsoft.Extensions.Options;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;

namespace ADApiService.Services
{
    public class AdService : IAdService
    {
        private readonly AdSettings _adSettings;
        private readonly ILogger<AdService> _logger;

        public AdService(IOptions<AdSettings> adSettings, ILogger<AdService> logger)
        {
            _adSettings = adSettings.Value;
            _logger = logger;
        }

        private PrincipalContext GetPrincipalContext(string domain)
        {
            // Connect to the specific domain controller for the target domain if needed,
            // or let AD handle it by just providing the domain name.
            return new PrincipalContext(ContextType.Domain, domain);
        }
        
        private bool IsUserHighPrivilege(ClaimsPrincipal callingUser)
        {
            var userGroups = GetUserGroupSids(callingUser);
            // This requires resolving SIDs to names, which is resource-intensive.
            // A more optimized approach might cache group memberships.
            using var context = new PrincipalContext(ContextType.Domain, _adSettings.ForestRootDomain);
            foreach (var sid in userGroups)
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
                    _logger.LogWarning(ex, "Could not resolve SID {Sid} to a group name.", sid);
                }
            }
            return false;
        }

        private List<string> GetUserGroupSids(ClaimsPrincipal user)
        {
            return user.FindAll(ClaimTypes.GroupSid).Select(c => c.Value).ToList();
        }

        public async Task<bool> CreateUserAsync(ClaimsPrincipal callingUser, CreateUserRequest request)
        {
            // Full implementation logic will go here.
            // For now, this is a placeholder to ensure compilation.
            await Task.Yield(); // To make the method async
            
            if (!IsUserHighPrivilege(callingUser) && (request.CreateAdminAccount || (request.OptionalGroups != null && request.OptionalGroups.Any())))
            {
                 _logger.LogWarning("Security violation: User {user} attempted to create user with high privileges.", callingUser.Identity?.Name);
                 return false; // Non-privileged user trying to assign privileged groups/roles
            }

            // Corrected property name here:
            if (request.OptionalGroups != null)
            {
                foreach(var group in request.OptionalGroups)
                {
                    if (!_adSettings.Provisioning.OptionalGroupsForHighPrivilege.Contains(group, StringComparer.OrdinalIgnoreCase))
                    {
                         _logger.LogWarning("Security violation: User {user} attempted to assign a non-approved optional group: {group}", callingUser.Identity?.Name, group);
                         return false; // Attempt to assign a group not in the allowed list
                    }
                }
            }


            _logger.LogInformation("Placeholder for creating user {SamAccountName} in domain {Domain}", request.SamAccountName, request.Domain);
            return true;
        }

        public async Task<bool> UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request)
        {
             await Task.Yield(); // To make the method async
             _logger.LogInformation("Placeholder for updating user {SamAccountName} in domain {Domain}", request.SamAccountName, request.Domain);
            return true;
        }

        public async Task<UserDetailModel?> GetUserDetailsAsync(string domain, string samAccountName)
        {
            await Task.Yield(); // To make the method async
            _logger.LogInformation("Placeholder for getting details for user {SamAccountName}", samAccountName);
            return new UserDetailModel { SamAccountName = samAccountName, DisplayName = "Dummy User Details" };
        }

        public async Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter)
        {
            return await Task.Run(() =>
            {
                var users = new List<UserListItem>();
                try
                {
                    using var context = GetPrincipalContext(domain);
                    var userPrinc = new UserPrincipal(context);
                    
                    if (!string.IsNullOrWhiteSpace(nameFilter))
                    {
                        userPrinc.SamAccountName = $"*{nameFilter}*";
                    }
                    if (statusFilter.HasValue)
                    {
                        userPrinc.Enabled = statusFilter.Value;
                    }
                    
                    using var searcher = new PrincipalSearcher(userPrinc);
                    foreach (var result in searcher.FindAll())
                    {
                        if (result is UserPrincipal user)
                        {
                            // Add this logic to check for the admin account
                            var adminSam = $"{user.SamAccountName}-a";
                            var hasAdminAccount = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adminSam) != null;
        
                            users.Add(new UserListItem
                            {
                                DisplayName = user.DisplayName,
                                SamAccountName = user.SamAccountName,
                                EmailAddress = user.EmailAddress,
                                Enabled = user.Enabled ?? false,
                                HasAdminAccount = hasAdminAccount // Populate the new property
                            });
                        }
                    }
                }
                catch (Exception ex) { _logger.LogError(ex, "Error listing users in domain '{domain}'.", domain); }
                return users;
            });
        }

    }
}

