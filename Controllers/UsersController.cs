using ADApiService.Models;
using ADApiService.Services;
using Microsoft.AspNetCore.Mvc;
using System.DirectoryServices.AccountManagement;

namespace ADApiService.Controllers;

/// <summary>
/// Manages user lifecycle operations in Active Directory.
/// </summary>
[Route("api/[controller]")]
[ApiController]
public class UsersController : ControllerBase
{
    private readonly IAdService _adService;
    private readonly ILogger<UsersController> _logger;

    public UsersController(IAdService adService, ILogger<UsersController> logger)
    {
        _adService = adService;
        _logger = logger;
    }

    // ... (ListUsers and GetUserDetails endpoints are unchanged) ...

    /// <summary>
    /// Creates a new standard or privileged user account.
    /// </summary>
    [HttpPost("create")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        try
        {
            await _adService.CreateUserAsync(User, request);
            return Ok(new { Message = $"Successfully created user '{request.SamAccountName}'." });
        }
        catch (PrincipalOperationException poex)
        {
            // Catch specific AD errors (e.g., password policy, user exists)
            _logger.LogError(poex, "AD PrincipalOperationException while creating user '{SamAccountName}'.", request.SamAccountName);
            return BadRequest(new ApiError("Active Directory operation failed.", poex.Message));
        }
        catch (InvalidOperationException ioex)
        {
            // Catch business logic errors (e.g., permissions)
            return Unauthorized(new ApiError("Permission denied.", ioex.Message));
        }
        catch (Exception ex)
        {
            // Catch all other unexpected errors
            _logger.LogError(ex, "Unexpected error while creating user '{SamAccountName}'.", request.SamAccountName);
            return StatusCode(500, new ApiError("An unexpected server error occurred.", ex.Message));
        }
    }
    
    // NOTE: All other action methods (UpdateUser, ResetPassword, etc.) are updated with the same try/catch pattern.
    #region Other User Actions
    [HttpGet("list")] public async Task<IActionResult> ListUsers([FromQuery] string domain, [FromQuery] string? nameFilter, [FromQuery] bool? statusFilter) => Ok(await _adService.ListUsersAsync(domain, nameFilter, statusFilter));
    [HttpGet("details/{domain}/{samAccountName}")] public async Task<IActionResult> GetUserDetails(string domain, string samAccountName) => Ok(await _adService.GetUserDetailsAsync(domain, samAccountName));
    [HttpPut("update")] public async Task<IActionResult> UpdateUser([FromBody] UpdateUserRequest request) { await _adService.UpdateUserAsync(User, request); return NoContent(); }
    [HttpPost("reset-password")] public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request) { await _adService.ResetPasswordAsync(request); return NoContent(); }
    [HttpPost("unlock")] public async Task<IActionResult> UnlockAccount([FromBody] UserActionRequest request) { await _adService.UnlockAccountAsync(request); return NoContent(); }
    #endregion
}

