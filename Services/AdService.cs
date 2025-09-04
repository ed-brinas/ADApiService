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
            var userOu = GetDistinguishedName(_adSettings.OUs.DefaultUsers, domainConfig.Name);

            // Create a PrincipalContext scoped to the specific OU for user creation.
            using var userCreationContext = GetPrincipalContext(domainConfig, userOu);

            // 1. Create Standard User within the scoped context.
            var standardUserPrincipal = new UserPrincipal(userCreationContext)
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
            
            // Save the user. It will be created in the OU defined in the userCreationContext.
            standardUserPrincipal.Save();
            _logger.LogInformation("Successfully created standard user '{SamAccountName}' in OU '{OU}'", request.SamAccountName, userOu);
            
            // Use a domain-level context for group operations, as groups can be anywhere in the domain.
            using var domainContext = GetPrincipalContext(domainConfig);

            // Add to default group
            AddUserToGroup(domainContext, request.SamAccountName, _adSettings.Groups.DefaultUserGroup);

            // Add to additional groups if requester has privileges
            if (IsHighPrivilege(requester) && request.AdditionalGroups != null)
            {
                foreach (var groupName in request.AdditionalGroups)
                {
                    // Security check: Only allow adding to pre-defined assignable groups
                    if(_adSettings.Roles.AssignableGroups.Contains(groupName, StringComparer.OrdinalIgnoreCase))
                    {
                        AddUserToGroup(domainContext, request.SamAccountName, groupName);
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
                var adminOu = GetDistinguishedName(_adSettings.OUs.AdminUsers, domainConfig.Name);
                var adminSam = $"{request.SamAccountName}-a";
                var adminDisplayName = $"admin-{request.FirstName}{request.LastName}";

                // Create a context specifically for the admin OU.
                using var adminCreationContext = GetPrincipalContext(domainConfig, adminOu);

                var adminUserPrincipal = new UserPrincipal(adminCreationContext)
                {
                    SamAccountName = adminSam,
                    UserPrincipalName = $"{adminSam}@{domainConfig.Name}",
                    DisplayName = adminDisplayName,
                    Enabled = true,
                    PasswordNotRequired = false
                };
                adminUserPrincipal.SetPassword(request.Password);
                
                // Save the admin user.
                adminUserPrincipal.Save();
                _logger.LogInformation("Successfully created admin user '{AdminSam}' in OU '{AdminOU}'", adminSam, adminOu);

                // Use the domain-level context to add the new user to the privileged group.
                AddUserToGroup(domainContext, adminSam, _adSettings.Groups.PrivilegedAdminGroup);
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

        private PrincipalContext GetPrincipalContext(DomainSettings domainConfig, string? container = null)
        {
            try
            {
                // If a container (OU) is specified, create the context scoped to that container.
                if (!string.IsNullOrEmpty(container))
                {
                    return new PrincipalContext(ContextType.Domain, domainConfig.DomainController, container);
                }
                // Otherwise, create a context for the entire domain.
                return new PrincipalContext(ContextType.Domain, domainConfig.DomainController);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create PrincipalContext for domain controller '{DC}' and container '{Container}'", domainConfig.DomainController, container ?? "N/A");
                throw new InvalidOperationException($"Could not connect to Active Directory on '{domainConfig.DomainController}'. Check configuration and network connectivity.", ex);
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

