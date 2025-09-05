using ADApiService.Models;
using Microsoft.Extensions.Options;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;

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

    public async Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter)
    {
        return await Task.Run(() =>
        {
            _logger.LogInformation("--- Starting User Search for domain: {Domain} ---", domain);
            var users = new List<UserListItem>();
            var domainDc = $"DC={domain.Replace(".", ",DC=")}";

            var allConfiguredOus = _adSettings.Provisioning.SearchBaseOus;
            _logger.LogDebug("All configured SearchBaseOus: {OUs}", string.Join("; ", allConfiguredOus));

            var relevantOus = allConfiguredOus
                .Where(ou => ou.EndsWith(domainDc, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (!relevantOus.Any())
            {
                _logger.LogWarning("CONFIGURATION_ISSUE: No SearchBaseOus in config match the domain '{Domain}'. Search cannot proceed.", domain);
                return Enumerable.Empty<UserListItem>();
            }

            _logger.LogInformation("Found {Count} relevant OUs to search for domain '{Domain}': {RelevantOus}", relevantOus.Count, string.Join("; ", relevantOus));

            foreach (var ou in relevantOus)
            {
                try
                {
                    _logger.LogInformation("Attempting to connect to PrincipalContext for OU: '{OU}'", ou);
                    using var context = new PrincipalContext(ContextType.Domain, domain, ou);
                    _logger.LogDebug("Successfully connected to PrincipalContext for OU: '{OU}'", ou);

                    using var userPrinc = new UserPrincipal(context);

                    // Apply filters
                    if (!string.IsNullOrWhiteSpace(nameFilter))
                    {
                        // Wildcard is needed for 'contains' search
                        userPrinc.SamAccountName = $"*{nameFilter}*";
                    }
                    if (statusFilter.HasValue)
                    {
                        userPrinc.Enabled = statusFilter.Value;
                    }

                    _logger.LogDebug("Searching in OU '{OU}' with filter [SAM: '{SamFilter}', Enabled: '{EnabledFilter}']", ou, userPrinc.SamAccountName, userPrinc.Enabled);

                    using var searcher = new PrincipalSearcher(userPrinc);
                    var results = searcher.FindAll().OfType<UserPrincipal>().ToList();
                    
                    _logger.LogInformation("Found {Count} user(s) in OU '{OU}' that match the filter.", results.Count, ou);

                    foreach (var result in results)
                    {
                        using(result)
                        {
                            users.Add(new UserListItem
                            {
                                DisplayName = result.DisplayName,
                                SamAccountName = result.SamAccountName,
                                EmailAddress = result.EmailAddress,
                                Enabled = result.Enabled ?? false,
                                // Skipping admin check for now to simplify debugging
                                HasAdminAccount = false 
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "PERMISSION_OR_PATH_ERROR: Failed to search in OU '{OU}'. Check if the path is correct and if the application's user has read permissions.", ou);
                }
            }
            _logger.LogInformation("--- User Search Finished. Total users found: {Count} ---", users.Count);
            return users;
        });
    }

    // NOTE: The rest of the methods are unchanged and omitted for brevity.
    // They will need to be restored after debugging.
    #region Unchanged Methods
    public async Task<UserDetailModel?> GetUserDetailsAsync(string domain, string samAccountName) { await Task.Yield(); throw new NotImplementedException(); }
    public async Task<bool> CreateUserAsync(ClaimsPrincipal callingUser, CreateUserRequest request) { await Task.Yield(); throw new NotImplementedException(); }
    public async Task<bool> UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request) { await Task.Yield(); throw new NotImplementedException(); }
    public async Task<bool> ResetPasswordAsync(ResetPasswordRequest request) { await Task.Yield(); throw new NotImplementedException(); }
    public async Task<bool> UnlockAccountAsync(UserActionRequest request) { await Task.Yield(); throw new NotImplementedException(); }
    #endregion
}

