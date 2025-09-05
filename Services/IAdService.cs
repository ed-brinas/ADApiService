using System.Security.Claims;
using ADApiService.Models;

namespace ADApiService.Services;

/// <summary>
/// Defines the contract for the Active Directory service, abstracting all AD operations.
/// </summary>
public interface IAdService
{
    /// <summary>
    /// Searches for users within configured OUs in a specific domain.
    /// </summary>
    /// <param name="domain">The domain to search in.</param>
    /// <param name="nameFilter">A filter for the user's name or sAMAccountName.</param>
    /// <param name="statusFilter">A filter for the user's account enabled/disabled status.</param>
    /// <returns>A collection of matching users.</returns>
    Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter);

    /// <summary>
    /// Retrieves detailed information for a single user account.
    /// </summary>
    /// <param name="domain">The domain where the user resides.</param>
    /// <param name="samAccountName">The sAMAccountName of the user.</param>
    /// <returns>Detailed information about the user, or null if not found.</returns>
    Task<UserDetailModel?> GetUserDetailsAsync(string domain, string samAccountName);

    /// <summary>
    /// Creates a new user account in Active Directory.
    /// </summary>
    /// <param name="callingUser">The authenticated principal performing the action.</param>
    /// <param name="request">The details of the user to create.</param>
    /// <returns>A detailed response object containing the created user's information and initial passwords.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the calling user lacks sufficient permissions.</exception>
    /// <exception cref="System.DirectoryServices.AccountManagement.PrincipalOperationException">Thrown for AD-specific errors (e.g., password policy).</exception>
    Task<CreateUserResponse> CreateUserAsync(ClaimsPrincipal callingUser, CreateUserRequest request);
    
    /// <summary>
    /// Updates an existing user's group memberships and/or manages their associated admin account.
    /// </summary>
    /// <param name="callingUser">The authenticated principal performing the action.</param>
    /// <param name="request">The details of the user update.</param>
    Task UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request);

    /// <summary>
    /// Resets the password for a user account.
    /// </summary>
    /// <param name="request">The details for the password reset.</param>
    Task ResetPasswordAsync(ResetPasswordRequest request);

    /// <summary>
    /// Unlocks a locked user account.
    /// </summary>
    /// <param name="request">The details of the user to unlock.</param>
    Task UnlockAccountAsync(UserActionRequest request);
}

