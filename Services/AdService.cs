using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using ADApiService.Models;
using Microsoft.Extensions.Options;

namespace ADApiService.Services
{
    /// <summary>
    /// Implements the IAdService interface to perform Active Directory operations.
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

        public async Task<(UserResponse? StandardUser, UserResponse? AdminUser)> CreateUserAsync(CreateUserRequest request, ClaimsPrincipal requester)
        {
            var domainConfig = GetDomainConfig(request.Domain);
            using var context = GetPrincipalContext(domainConfig);

            // 1. Create Standard User
            var standardUserPrincipal = new UserPrincipal(context)
            {
                SamAccountName = request.SamAccountName,
                UserPrincipalName = $"{request.SamAccountName}@{domainConfig.Name}",
                DisplayName = $"{request.FirstName} {request.LastName}",
                GivenName = request.FirstName,
                Surname = request.LastName,
                EmailAddress = request.Email,
                Enabled = true,
                PasswordNotRequired = false,
                UserCannotChangePassword = false
            };

            standardUserPrincipal.SetPassword(request.Password);
            
            var userOu = GetDistinguishedName(_adSettings.OUs.DefaultUsers, domainConfig.Name);
            standardUserPrincipal.Save(userOu);
            _logger.LogInformation("Successfully created standard user '{SamAccountName}' in OU '{OU}'", request.SamAccountName, userOu);
            
            // Add to default group
            AddUserToGroup(context, request.SamAccountName, _adSettings.Groups.DefaultUserGroup);

            // Add to additional groups if requester has privileges
            if (IsHighPrivilege(requester) && request.AdditionalGroups != null)
            {
                foreach (var groupName in request.AdditionalGroups)
                {
                    // Security check: Only allow adding to pre-defined assignable groups
                    if(_adSettings.Roles.AssignableGroups.Contains(groupName, StringComparer.OrdinalIgnoreCase))
                    {
                        AddUserToGroup(context, request.SamAccountName, groupName);
                    }
                    else
                    {
                         _logger.LogWarning("Skipping group '{GroupName}' assignment for user '{SamAccountName}' as it is not in the assignable groups list.", groupName, request.SamAccountName);
                    }
                }
            }

            var standardUserResponse = MapUserToResponse(standardUserPrincipal);
            UserResponse? adminUserResponse = null;

            // 2. Create Privileged Admin User (if requester has rights)
            if (IsHighPrivilege(requester))
            {
                var adminSam = $"{request.SamAccountName}-a";
                var adminDisplayName = $"admin-{request.FirstName}{request.LastName}";
                var adminContext = GetPrincipalContext(domainConfig);

                var adminUserPrincipal = new UserPrincipal(adminContext)
                {
                    SamAccountName = adminSam,
                    UserPrincipalName = $"{adminSam}@{domainConfig.Name}",
                    DisplayName = adminDisplayName,
                    Enabled = true,
                    PasswordNotRequired = false
                };
                adminUserPrincipal.SetPassword(request.Password);
                
                var adminOu = GetDistinguishedName(_adSettings.OUs.AdminUsers, domainConfig.Name);
                adminUserPrincipal.Save(adminOu);

                _logger.LogInformation("Successfully created admin user '{AdminSam}' in OU '{AdminOU}'", adminSam, adminOu);

                AddUserToGroup(adminContext, adminSam, _adSettings.Groups.PrivilegedAdminGroup);
                adminUserResponse = MapUserToResponse(adminUserPrincipal);
            }
            
            return (standardUserResponse, adminUserResponse);
        }

        public IEnumerable<UserResponse> ListUsers(string domain, string? groupFilter, string? nameFilter, bool? statusFilter)
        {
            var domainConfig = GetDomainConfig(domain);
            using var context = GetPrincipalContext(domainConfig);
            
            var userPrincipal = new UserPrincipal(context);
            
            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                userPrincipal.SamAccountName = $"*{nameFilter}*";
            }

            if (statusFilter.HasValue)
            {
                userPrincipal.Enabled = statusFilter.Value;
            }

            using var searcher = new PrincipalSearcher(userPrincipal);
            var users = searcher.FindAll().OfType<UserPrincipal>();

            if (!string.IsNullOrWhiteSpace(groupFilter))
            {
                var group = GroupPrincipal.FindByIdentity(context, groupFilter);
                if (group != null)
                {
                    users = users.Where(u => u.IsMemberOf(group));
                }
                else
                {
                    // If group is not found, return empty list
                    return Enumerable.Empty<UserResponse>();
                }
            }
            
            return users.Select(MapUserToResponse).ToList();
        }

        public async Task ResetPasswordAsync(ResetPasswordRequest request)
        {
            await Task.Run(() =>
            {
                var domainConfig = GetDomainConfig(request.Domain);
                using var context = GetPrincipalContext(domainConfig);
                var user = UserPrincipal.FindByIdentity(context, request.SamAccountName);
                if (user == null)
                {
                    throw new KeyNotFoundException($"User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
                }
                user.SetPassword(request.NewPassword);
                user.UnlockAccount(); // Resetting password often implies unlocking it too.
                user.Save();
                _logger.LogInformation("Password reset and account unlocked for user '{SamAccountName}'", request.SamAccountName);
            });
        }

        public async Task UnlockAccountAsync(UnlockAccountRequest request)
        {
             await Task.Run(() =>
            {
                var domainConfig = GetDomainConfig(request.Domain);
                using var context = GetPrincipalContext(domainConfig);
                var user = UserPrincipal.FindByIdentity(context, request.SamAccountName);
                if (user == null)
                {
                    throw new KeyNotFoundException($"User '{request.SamAccountName}' not found in domain '{request.Domain}'.");
                }
                if (user.IsAccountLockedOut())
                {
                    user.UnlockAccount();
                    user.Save();
                    _logger.LogInformation("Account unlocked for user '{SamAccountName}'", request.SamAccountName);
                }
                else
                {
                    _logger.LogInformation("Account for user '{SamAccountName}' was not locked.", request.SamAccountName);
                }
            });
        }
        
        /// <summary>
        /// Checks if the user is a member of any high-privilege groups defined in config.
        /// </summary>
        public bool IsHighPrivilege(ClaimsPrincipal user)
        {
            return _adSettings.Roles.AccountCreation.Any(role => user.IsInRole(role));
        }
        
        // --- Private Helper Methods ---

        private PrincipalContext GetPrincipalContext(DomainSettings domainConfig)
        {
            try
            {
                return new PrincipalContext(ContextType.Domain, domainConfig.DomainController);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create PrincipalContext for domain controller '{DC}'", domainConfig.DomainController);
                throw new InvalidOperationException($"Could not connect to Active Directory domain controller '{domainConfig.DomainController}'. Check configuration and network connectivity.", ex);
            }
        }
        
        private DomainSettings GetDomainConfig(string domainName)
        {
            var domainConfig = _adSettings.Domains.FirstOrDefault(d => d.Name.Equals(domainName, StringComparison.OrdinalIgnoreCase));
            if (domainConfig == null)
            {
                _logger.LogError("Configuration for domain '{DomainName}' not found in appsettings.json", domainName);
                throw new ArgumentException($"Invalid or unsupported domain specified: {domainName}");
            }
            return domainConfig;
        }

        private void AddUserToGroup(PrincipalContext context, string samAccountName, string groupName)
        {
            try
            {
                var group = GroupPrincipal.FindByIdentity(context, groupName);
                if (group != null)
                {
                    group.Members.Add(context, IdentityType.SamAccountName, samAccountName);
                    group.Save();
                    _logger.LogInformation("Added user '{SamAccountName}' to group '{GroupName}'", samAccountName, groupName);
                }
                else
                {
                    _logger.LogWarning("Group '{GroupName}' not found. Could not add user '{SamAccountName}'.", groupName, samAccountName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to add user '{SamAccountName}' to group '{GroupName}'", samAccountName, groupName);
                // Decide if this should throw or just log. Logging is safer for non-critical group adds.
            }
        }
        
        private static string GetDistinguishedName(string ouPath, string domain)
        {
            var domainComponents = domain.Split('.').Select(dc => $"DC={dc}");
            return $"{ouPath},{string.Join(",", domainComponents)}";
        }
        
        private static UserResponse MapUserToResponse(UserPrincipal user)
        {
            return new UserResponse
            {
                DistinguishedName = user.DistinguishedName,
                SamAccountName = user.SamAccountName,
                DisplayName = user.DisplayName,
                UserPrincipalName = user.UserPrincipalName,
                EmailAddress = user.EmailAddress,
                Enabled = user.Enabled,
                LastLogon = user.LastLogon
            };
        }
    }
}

