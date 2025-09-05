using System.Security.Claims;
using ADApiService.Models;

namespace ADApiService.Services;

/// <summary>
/// Defines the contract for the Active Directory management service.
/// </summary>
public interface IAdService
{
    /// <summary>
    /// Searches for users within configured OUs in a specific domain.
    /// </summary>
    /// <param name="domain">The domain to search in.</param>
    /// <param name="nameFilter">A filter for the user's name or sAMAccountName.</param>
    /// <param name="statusFilter">A filter for the user's account status (enabled/disabled).</param>
    /// <returns>A collection of users matching the criteria.</returns>
    Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter);

    /// <summary>
    /// Retrieves detailed information for a single user account.
    /// </summary>
    /// <param name="domain">The user's domain.</param>
    /// <param name="samAccountName">The user's sAMAccountName.</param>
    /// <returns>Detailed information for the user, or null if not found.</returns>
    Task<UserDetailModel?> GetUserDetailsAsync(string domain, string samAccountName);
    
    /// <summary>
    /// Creates a new standard user and, optionally, an associated admin account.
    /// </summary>
    /// <param name="callingUser">The ClaimsPrincipal of the user performing the action.</param>
    /// <param name="request">The details of the user to create.</param>
    /// <returns>True if the user was created successfully; otherwise, false.</returns>
    Task<bool> CreateUserAsync(ClaimsPrincipal callingUser, CreateUserRequest request);

    /// <summary>
    /// Updates an existing user's group memberships and associated admin account status.
    /// </summary>
    /// <param name="callingUser">The ClaimsPrincipal of the user performing the action.</param>
    /// <param name="request">The update request details.</param>
    /// <returns>True if the user was updated successfully; otherwise, false.</returns>
    Task<bool> UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request);
    
    /// <summary>
    /// Resets a user's password.
    /// </summary>
    /// <param name="request">The password reset request details.</param>
    /// <returns>True if the password was reset successfully; otherwise, false.</returns>
    Task<bool> ResetPasswordAsync(ResetPasswordRequest request);

    /// <summary>
    /// Unlocks a locked user account.
    /// </summary>
    /// <param name="request">The unlock request details.</param>
    /// <returns>True if the account was unlocked successfully; otherwise, false.</returns>
    Task<bool> UnlockAccountAsync(UserActionRequest request);
}

