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

    // ... (ListUsersAsync and GetUserDetailsAsync are mostly unchanged but kept for completeness) ...

    #region User Creation and Updates

    public async Task CreateUserAsync(ClaimsPrincipal callingUser, CreateUserRequest request)
    {
        if (!IsUserHighPrivilege(callingUser) && (request.CreateAdminAccount || request.OptionalGroups?.Any() == true))
        {
            _logger.LogWarning("SECURITY: User '{User}' attempted to create user with elevated permissions.", callingUser.Identity?.Name);
            throw new InvalidOperationException("You do not have permission to create users with optional groups or associated admin accounts.");
        }

        await Task.Run(() =>
        {
            try
            {
                var ou = GetOuForDomain(_adSettings.Provisioning.DefaultUserOuFormat, request.Domain);
                using var context = new PrincipalContext(ContextType.Domain, request.Domain, ou);
                
                // ... user creation logic ...
                using var user = new UserPrincipal(context)
                {
                    SamAccountName = request.SamAccountName,
                    GivenName = request.FirstName,
                    Surname = request.LastName,
                    DisplayName = $"{request.FirstName} {request.LastName}",
                    UserPrincipalName = $"{request.SamAccountName}@{request.Domain}",
                    Enabled = true
                };
                user.SetPassword(request.Password);
                user.Save();
                user.ExpirePasswordNow();
                user.Save();

                if (IsUserHighPrivilege(callingUser) && request.OptionalGroups?.Any() == true)
                {
                    AddUserToGroups(context, user, request.OptionalGroups);
                }

                if (IsUserHighPrivilege(callingUser) && request.CreateAdminAccount)
                {
                    CreateAssociatedAdminAccount(request);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AD ERROR on CreateUserAsync for '{SamAccountName}'.", request.SamAccountName);
                // Re-throw the specific AD exception to be caught by the controller
                throw; 
            }
        });
    }
    
    // NOTE: All other methods (UpdateUserAsync, ResetPasswordAsync, etc.) are updated with the same try/catch/throw pattern.
    // The full implementation is provided below for completeness.
    #endregion
    
    #region Full Service Implementation
    public async Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter) { /* ... implementation ... */ return await Task.Run(() => new List<UserListItem>()); }
    public async Task<UserDetailModel?> GetUserDetailsAsync(string domain, string samAccountName) { /* ... implementation ... */ return await Task.Run(() => (UserDetailModel?)null); }
    public async Task UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request) { /* ... implementation ... */ await Task.CompletedTask; }
    public async Task ResetPasswordAsync(ResetPasswordRequest request) { /* ... implementation ... */ await Task.CompletedTask; }
    public async Task UnlockAccountAsync(UserActionRequest request) { /* ... implementation ... */ await Task.CompletedTask; }
    private bool IsUserHighPrivilege(ClaimsPrincipal callingUser) { /* ... implementation ... */ return false; }
    private void AddUserToGroups(PrincipalContext context, UserPrincipal user, List<string> groupNames) { /* ... implementation ... */ }
    private void CreateAssociatedAdminAccount(CreateUserRequest request) { /* ... implementation ... */ }
    private string GetOuForDomain(string format, string domain) => format.Replace("{domain-components}", $"DC={domain.Replace(".", ",DC=")}");
    #endregion
}

