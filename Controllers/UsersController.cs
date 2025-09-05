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

    /// <summary>
    /// Searches for users within configured OUs.
    /// </summary>
    /// <param name="domain">The domain to search in.</param>
    /// <param name="nameFilter">A filter for name or sAMAccountName.</param>
    /// <param name="statusFilter">Filter by account status (true=enabled, false=disabled).</param>
    /// <returns>A list of matching users.</returns>
    [HttpGet("list")]
    [ProducesResponseType(typeof(IEnumerable<UserListItem>), 200)]
    public async Task<IActionResult> ListUsers([FromQuery] string domain, [FromQuery] string? nameFilter, [FromQuery] bool? statusFilter)
    {
        var users = await _adService.ListUsersAsync(domain, nameFilter, statusFilter);
        return Ok(users);
    }

    /// <summary>
    /// Retrieves detailed information for a single user.
    /// </summary>
    /// <param name="domain">The domain of the user.</param>
    /// <param name="samAccountName">The sAMAccountName of the user.</param>
    /// <returns>Detailed user information.</returns>
    [HttpGet("details/{domain}/{samAccountName}")]
    [ProducesResponseType(typeof(UserDetailModel), 200)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> GetUserDetails(string domain, string samAccountName)
    {
        var userDetails = await _adService.GetUserDetailsAsync(domain, samAccountName);
        if (userDetails == null)
        {
            return NotFound();
        }
        return Ok(userDetails);
    }

    /// <summary>
    /// Creates a new standard or privileged user account.
    /// </summary>
    /// <returns>Detailed information about the created account(s), including initial passwords.</returns>
    [HttpPost("create")]
    [ProducesResponseType(typeof(CreateUserResponse), 200)]
    [ProducesResponseType(typeof(ApiError), 400)]
    [ProducesResponseType(typeof(ApiError), 401)]
    [ProducesResponseType(typeof(ApiError), 500)]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        try
        {
            var response = await _adService.CreateUserAsync(User, request);
            return Ok(response);
        }
        catch (PrincipalOperationException poex)
        {
            _logger.LogError(poex, "AD PrincipalOperationException while creating user '{SamAccountName}'.", request.SamAccountName);
            return BadRequest(new ApiError("Active Directory operation failed.", poex.Message));
        }
        catch (InvalidOperationException ioex)
        {
            return Unauthorized(new ApiError("Permission denied.", ioex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while creating user '{SamAccountName}'.", request.SamAccountName);
            return StatusCode(500, new ApiError("An unexpected server error occurred.", ex.Message));
        }
    }
    
    /// <summary>
    /// Updates a user's group memberships and/or manages their associated admin account.
    /// </summary>
    [HttpPut("update")]
    [ProducesResponseType(204)]
    [ProducesResponseType(typeof(ApiError), 400)]
    public async Task<IActionResult> UpdateUser([FromBody] UpdateUserRequest request) 
    { 
        try
        {
            await _adService.UpdateUserAsync(User, request);
            return NoContent();
        }
        catch (Exception ex)
        {
            return BadRequest(new ApiError("Failed to update user.", ex.Message));
        }
    }

    /// <summary>
    /// Resets a user's password.
    /// </summary>
    [HttpPost("reset-password")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request) 
    { 
        try
        {
            await _adService.ResetPasswordAsync(request);
            return NoContent();
        }
        catch (Exception ex)
        {
            return BadRequest(new ApiError("Failed to reset password.", ex.Message));
        }
    }

    /// <summary>
    /// Unlocks a user's account.
    /// </summary>
    [HttpPost("unlock")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> UnlockAccount([FromBody] UserActionRequest request)
    {
        try
        {
            await _adService.UnlockAccountAsync(request);
            return NoContent();
        }
        catch (Exception ex)
        {
            return BadRequest(new ApiError("Failed to unlock account.", ex.Message));
        }
    }
}

