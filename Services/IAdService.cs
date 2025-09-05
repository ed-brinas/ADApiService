using System.Security.Claims;
using ADApiService.Models;

namespace ADApiService.Services;

/// <summary>
/// Defines the contract for the Active Directory service.
/// </summary>
public interface IAdService
{
    Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter);
    Task<UserDetailModel?> GetUserDetailsAsync(string domain, string samAccountName);
    Task<CreateUserResponse> CreateUserAsync(ClaimsPrincipal callingUser, CreateUserRequest request);
    Task UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request);
    Task<string> ResetPasswordAsync(UserActionRequest request);
    Task UnlockAccountAsync(UserActionRequest request);
}

