using ADApiService.Models;
using System.Security.Claims;

namespace ADApiService.Services
{
    public interface IAdService
    {
        Task<bool> CreateUserAsync(ClaimsPrincipal callingUser, CreateUserRequest request);
        Task<bool> UpdateUserAsync(ClaimsPrincipal callingUser, UpdateUserRequest request);
        Task<UserDetailModel?> GetUserDetailsAsync(string domain, string samAccountName);
        Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter);
    }
}

