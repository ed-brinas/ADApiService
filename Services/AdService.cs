using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using ADApiService.Models;
using Microsoft.Extensions.Options;

namespace ADApiService.Services;

public class AdService : IAdService
{
    private readonly AdSettings _adSettings;
    private readonly ILogger<AdService> _logger;

    public AdService(IOptions<AdSettings> adSettings, ILogger<AdService> logger)
    {
        _adSettings = adSettings.Value;
        _logger = logger;
    }

    public UserContext GetUserContext(IPrincipal user)
    {
        using var context = new PrincipalContext(ContextType.Domain, _adSettings.ForestRootDomain);
        var principal = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, user.Identity!.Name);

        if (principal == null) throw new InvalidOperationException("Could not find the calling user in Active Directory.");
        
        var isHighPrivilege = _adSettings.AccessControl.HighPrivilegeGroups
            .Any(group => user.IsInRole(group));

        return new UserContext
        {
            Name = principal.DisplayName ?? user.Identity.Name!,
            IsHighPrivilege = isHighPrivilege
        };
    }

    public async Task CreateUserAsync(CreateUserRequest request, IPrincipal callingUser)
    {
        await Task.Run(() =>
        {
            using var context = new PrincipalContext(ContextType.Domain, request.Domain);
            var userPrincipal = new UserPrincipal(context)
            {
                SamAccountName = request.SamAccountName,
                GivenName = request.FirstName,
                Surname = request.LastName,
                DisplayName = $"{request.FirstName} {request.LastName}",
                UserPrincipalName = $"{request.SamAccountName}@{request.Domain}",
                Enabled = true,
                PasswordNeverExpires = false
            };
            userPrincipal.SetPassword(request.Password);
            
            var ou = string.Format(_adSettings.DefaultUserOuFormat, request.Domain.Split('.'));
            userPrincipal.Save(ou);
            
            // Add to default groups
            foreach (var groupName in _adSettings.Provisioning.DefaultUserGroups)
            {
                var group = GroupPrincipal.FindByIdentity(context, groupName);
                if (group != null) group.Members.Add(userPrincipal);
            }
        });
    }

    public async Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter)
    {
        return await Task.Run(() =>
        {
            using var context = new PrincipalContext(ContextType.Domain, domain);
            using var searchPrincipal = new UserPrincipal(context);

            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                searchPrincipal.SamAccountName = $"*{nameFilter}*";
            }
            if (statusFilter.HasValue)
            {
                searchPrincipal.Enabled = statusFilter.Value;
            }

            using var searcher = new PrincipalSearcher(searchPrincipal);
            return searcher.FindAll()
                .OfType<UserPrincipal>()
                .Select(u => new UserListItem
                {
                    DisplayName = u.DisplayName,
                    SamAccountName = u.SamAccountName,
                    EmailAddress = u.EmailAddress,
                    Enabled = u.Enabled ?? false
                })
                .OrderBy(u => u.DisplayName)
                .ToList();
        });
    }

    public async Task ResetPasswordAsync(string domain, string samAccountName, string newPassword)
    {
        await Task.Run(() =>
        {
            using var context = new PrincipalContext(ContextType.Domain, domain);
            var user = UserPrincipal.FindByIdentity(context, samAccountName);
            if (user == null) throw new KeyNotFoundException("User not found.");
            
            user.SetPassword(newPassword);
            if (user.IsAccountLockedOut())
            {
                user.UnlockAccount();
            }
        });
    }

    public async Task UnlockAccountAsync(string domain, string samAccountName)
    {
        await Task.Run(() =>
        {
            using var context = new PrincipalContext(ContextType.Domain, domain);
            var user = UserPrincipal.FindByIdentity(context, samAccountName);
            if (user == null) throw new KeyNotFoundException("User not found.");

            if (user.IsAccountLockedOut())
            {
                user.UnlockAccount();
            }
        });
    }
}

