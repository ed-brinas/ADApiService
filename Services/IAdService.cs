using System.Security.Principal;
using ADApiService.Models;

namespace ADApiService.Services;

public interface IAdService
{
    UserContext GetUserContext(IPrincipal user);
    Task CreateUserAsync(CreateUserRequest request, IPrincipal callingUser);
    Task<IEnumerable<UserListItem>> ListUsersAsync(string domain, string? nameFilter, bool? statusFilter);
    Task ResetPasswordAsync(string domain, string samAccountName, string newPassword);
    Task UnlockAccountAsync(string domain, string samAccountName);
}

