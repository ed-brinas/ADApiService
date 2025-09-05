using ADApiService.Models;
using ADApiService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ADApiService.Controllers;

/// <summary>
/// API endpoints for managing Active Directory users.
/// </summary>
[Route("api/[controller]")]
[ApiController]
[Authorize]
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
    /// Searches for users based on specified criteria.
    /// </summary>
    [HttpGet("list")]
    [ProducesResponseType(typeof(IEnumerable<UserListItem>), StatusCodes.Status200OK)]
    public async Task<IActionResult> ListUsers([FromQuery] string domain, [FromQuery] string? nameFilter, [FromQuery] bool? statusFilter)
    {
        var users = await _adService.ListUsersAsync(domain, nameFilter, statusFilter);
        return Ok(users);
    }

    /// <summary>
    /// Gets detailed information for a single user.
    /// </summary>
    [HttpGet("details/{domain}/{samAccountName}")]
    [ProducesResponseType(typeof(UserDetailModel), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetUserDetails(string domain, string samAccountName)
    {
        var userDetails = await _adService.GetUserDetailsAsync(domain, samAccountName);
        if (userDetails == null)
        {
            return NotFound(new ApiError("User not found."));
        }
        return Ok(userDetails);
    }

    /// <summary>
    /// Creates a new user account.
    /// </summary>
    [HttpPost("create")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ApiError), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        var success = await _adService.CreateUserAsync(User, request);
        if (!success)
        {
            return BadRequest(new ApiError("Failed to create user. Check the API logs for details."));
        }
        return NoContent();
    }

    /// <summary>
    /// Updates an existing user's group membership and admin account status.
    /// </summary>
    [HttpPut("update")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ApiError), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> UpdateUser([FromBody] UpdateUserRequest request)
    {
        var success = await _adService.UpdateUserAsync(User, request);
        if (!success)
        {
            return BadRequest(new ApiError("Failed to update user. Check the API logs for details."));
        }
        return NoContent();
    }

    /// <summary>
    /// Resets a user's password.
    /// </summary>
    [HttpPost("reset-password")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ApiError), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var success = await _adService.ResetPasswordAsync(request);
        if (!success)
        {
            return BadRequest(new ApiError("Failed to reset password. The user may not exist or the password does not meet complexity requirements."));
        }
        return NoContent();
    }

    /// <summary>
    /// Unlocks a user's account.
    /// </summary>
    [HttpPost("unlock")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ApiError), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> UnlockAccount([FromBody] UserActionRequest request)
    {
        var success = await _adService.UnlockAccountAsync(request);
        if (!success)
        {
            return BadRequest(new ApiError("Failed to unlock account. The user may not exist."));
        }
        return NoContent();
    }
}

