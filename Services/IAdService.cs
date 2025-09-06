using System.Security.Claims;
using ADApiService.Models;

namespace ADApiService.Services;

/// <summary>
/// Defines the contract for the Active Directory service.
/// </summary>
public interface IAdService
{
    /// <summary>
    /// Retrieves a list of users from a specified domain, with optional filters.
    /// </summary>
    /// <param name="domain">The domain to search in.</param>
    /// <param name="nameFilter">A filter for the user's name, username, or email.</param>
    /// <param name="statusFilter">Filters users by their enabled/disabled status.</param>
    /// <param name="hasAdminAccountFilter">Filters users based on the existence of an associated admin account.</param>
    /// <returns>A list of users matching the criteria.</returns>
    Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter, bool? hasAdminAccountFilter);
    
    Task<UserDetailModel?> GetUserDetailsAsync(string domain, string samAccountName);
    Task<CreateUserResponse> CreateUserAsync(ClaimsPrincipal callingUser, CreateUserRequest request);
    Task UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request);
    Task<string> ResetPasswordAsync(UserActionRequest request);
    Task UnlockAccountAsync(UserActionRequest request);
    Task DisableAccountAsync(UserActionRequest request);
}
