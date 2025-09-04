using System.Security.Claims;
using ADApiService.Models;

namespace ADApiService.Services
{
    /// <summary>
    /// Defines the contract for Active Directory user management operations.
    /// </summary>
    public interface IAdService
    {
        Task<(UserResponse? StandardUser, UserResponse? AdminUser)> CreateUserAsync(CreateUserRequest request, ClaimsPrincipal requester);
        IEnumerable<UserResponse> ListUsers(string domain, string? groupFilter, string? nameFilter, bool? statusFilter);
        Task ResetPasswordAsync(ResetPasswordRequest request);
        Task UnlockAccountAsync(UnlockAccountRequest request);
        bool IsHighPrivilege(ClaimsPrincipal user);
    }
}
