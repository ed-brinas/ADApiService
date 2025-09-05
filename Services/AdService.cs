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

    // ... (ListUsersAsync and GetUserDetailsAsync are unchanged) ...

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
                
                // FIX: Removed 'ExpirePasswordNow' from the initializer.
                using var user = new UserPrincipal(context)
                {
                    SamAccountName = request.SamAccountName,
                    GivenName = request.FirstName,
                    Surname = request.LastName,
                    DisplayName = $"{request.FirstName} {request.LastName}",
                    Name = $"{request.FirstName} {request.LastName}",
                    PasswordNotRequired = false,
                    UserCannotChangePassword = false,
                    Enabled = true
                };
                user.SetPassword(request.Password);
                user.Save();

                // FIX: Call ExpirePasswordNow() as a method AFTER saving the user.
                user.ExpirePasswordNow();
                user.Save(); // Save the change

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
    
    // ... (UpdateUserAsync is unchanged) ...

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
                
                // FIX: Changed assignment to a method call.
                user.ExpirePasswordNow();
                
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

    // ... (UnlockAccountAsync is unchanged) ...

    #endregion

    #region Helper Methods
    
    // ... (IsUserHighPrivilege and GetUserGroupNames are unchanged) ...

    private bool CreateAssociatedAdminAccount(CreateUserRequest request)
    {
        try
        {
            var adminOu = GetOuForDomain(_adSettings.Provisioning.AdminUserOuFormat, request.Domain);
            using var context = new PrincipalContext(ContextType.Domain, request.Domain, adminOu);
            
            var adminSam = $"{request.SamAccountName}-a";
            var adminDisplayName = $"admin-{request.FirstName}{request.LastName}";
            _logger.LogInformation("Attempting to create admin account '{AdminSam}' in OU '{AdminOu}'.", adminSam, adminOu);

            // FIX: Removed 'ExpirePasswordNow' from the initializer.
            using var adminUser = new UserPrincipal(context)
            {
                SamAccountName = adminSam,
                DisplayName = adminDisplayName,
                Name = adminDisplayName,
                UserPrincipalName = $"{adminSam}@{request.Domain}",
                PasswordNotRequired = false,
                UserCannotChangePassword = false,
                Enabled = true
            };
            adminUser.SetPassword(GenerateRandomPassword());
            adminUser.Save();

            // FIX: Call ExpirePasswordNow() as a method AFTER saving the user.
            adminUser.ExpirePasswordNow();
            adminUser.Save(); // Save the change

            // Add to the designated admin group
            AddUserToGroups(context, adminUser, [_adSettings.Provisioning.AdminGroup]);
            _logger.LogInformation("Successfully created and configured admin account '{AdminSam}'.", adminSam);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create associated admin account for user '{SamAccountName}'.", request.SamAccountName);
            return false;
        }
    }
    
    // ... (The rest of the helper methods are unchanged) ...
    // NOTE: Unchanged methods have been omitted for brevity.
    public async Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter) { await Task.Yield(); throw new NotImplementedException(); }
    public async Task<UserDetailModel?> GetUserDetailsAsync(string domain, string samAccountName) { await Task.Yield(); throw new NotImplementedException(); }
    public async Task<bool> UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request) { await Task.Yield(); throw new NotImplementedException(); }
    public async Task<bool> UnlockAccountAsync(UserActionRequest request) { await Task.Yield(); throw new NotImplementedException(); }
    private bool IsUserHighPrivilege(ClaimsPrincipal callingUser) { throw new NotImplementedException(); }
    private List<string> GetUserGroupNames(ClaimsPrincipal user) { throw new NotImplementedException(); }
    private void AddUserToGroups(PrincipalContext context, UserPrincipal user, List<string> groupNames) { }
    private void UpdateGroupMembership(PrincipalContext context, UserPrincipal user, List<string> targetGroupNames) { }
    private string GetOuForDomain(string ouFormat, string domain) { throw new NotImplementedException(); }
    private string GenerateRandomPassword() { throw new NotImplementedException(); }

    #endregion
}

