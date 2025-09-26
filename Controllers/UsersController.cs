using KeyStone.Models;
using KeyStone.Services;
using Microsoft.AspNetCore.Mvc;
using System.DirectoryServices.AccountManagement;

namespace KeyStone.Controllers;

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
    /// Retrieves a list of users from a specified domain, with optional filters.
    /// </summary>
    [HttpGet("list")]
    [ProducesResponseType(typeof(IEnumerable<UserListItem>), 200)]
    public async Task<IActionResult> ListUsers([FromQuery] string domain, [FromQuery] string? nameFilter, [FromQuery] bool? statusFilter, [FromQuery] bool? hasAdminAccount)
    {
        var users = await _adService.ListUsersAsync(domain, nameFilter, statusFilter, hasAdminAccount);
        return Ok(users);
    }

    /// <summary>
    /// Gets detailed information for a single user account.
    /// </summary>
    [HttpGet("details/{domain}/{samAccountName}")]
    [ProducesResponseType(typeof(UserDetailModel), 200)]
    [ProducesResponseType(typeof(ApiError), 404)]
    public async Task<IActionResult> GetUserDetails(string domain, string samAccountName)
    {    
        var userDetails = await _adService.GetUserDetailsAsync(User, domain, samAccountName);
        if (userDetails == null)
        {
            return NotFound(new ApiError($"User '{samAccountName}' not found in domain '{domain}'."));
        }
        return Ok(userDetails);
    }

    /// <summary>
    /// Creates a new standard or privileged user account.
    /// </summary>
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
        catch (InvalidOperationException ioex)
        {
            return Unauthorized(new ApiError("Permission denied.", ioex.Message));
        }
        catch (PrincipalOperationException poex)
        {
            _logger.LogError(poex, "AD PrincipalOperationException while creating user '{SamAccountName}'.", request.SamAccountName);
            return BadRequest(new ApiError("Active Directory operation failed.", poex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while creating user '{SamAccountName}'.", request.SamAccountName);
            return StatusCode(500, new ApiError("An unexpected server error occurred.", ex.Message));
        }
    }

    /// <summary>
    /// Updates a user's optional group memberships and manages their associated admin account.
    /// </summary>
    [HttpPut("update")]
    [ProducesResponseType(204)]
    [ProducesResponseType(typeof(ApiError), 400)]
    [ProducesResponseType(typeof(ApiError), 401)]
    [ProducesResponseType(typeof(ApiError), 404)]
    [ProducesResponseType(typeof(ApiError), 500)]
    public async Task<IActionResult> UpdateUser([FromBody] UpdateUserRequest request)
    {
        try
        {
            await _adService.UpdateUserAsync(User, request);
            return NoContent();
        }
        catch (InvalidOperationException ioex)
        {
            return Unauthorized(new ApiError("Permission denied.", ioex.Message));
        }
        catch (KeyNotFoundException knfex)
        {
            return NotFound(new ApiError(knfex.Message));
        }
        catch (PrincipalOperationException poex)
        {
            _logger.LogError(poex, "AD PrincipalOperationException while updating user '{SamAccountName}'.", request.SamAccountName);
            return BadRequest(new ApiError("Active Directory operation failed.", poex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while updating user '{SamAccountName}'.", request.SamAccountName);
            return StatusCode(500, new ApiError("An unexpected server error occurred.", ex.Message));
        }
    }

    /// <summary>
    /// Resets a user's password to a new, randomly generated password.
    /// </summary>
    [HttpPost("reset-password")]
    [ProducesResponseType(typeof(object), 200)]
    [ProducesResponseType(typeof(ApiError), 404)]
    [ProducesResponseType(typeof(ApiError), 400)]
    [ProducesResponseType(typeof(ApiError), 500)]
    public async Task<IActionResult> ResetPassword([FromBody] UserActionRequest request)
    {
        try
        {
            var newPassword = await _adService.ResetPasswordAsync(request);
            return Ok(new { SamAccountName = request.SamAccountName, NewPassword = newPassword });
        }
        catch (KeyNotFoundException knfex)
        {
            return NotFound(new ApiError(knfex.Message));
        }
        catch (PrincipalOperationException poex)
        {
            return BadRequest(new ApiError("Active Directory operation failed.", poex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while resetting password for '{SamAccountName}'.", request.SamAccountName);
            return StatusCode(500, new ApiError("An unexpected server error occurred.", ex.Message));
        }
    }

    // Add this new method to UsersController.cs
    /// <summary>
    /// Resets the password for an associated admin account (-a account).
    /// </summary>
    /// <remarks>
    /// This is a high-privilege operation and is restricted to authorized users.
    /// The target account must reside in the configured Admin OU.
    /// </remarks>
    [HttpPost("reset-admin-password")]
    [ProducesResponseType(typeof(object), 200)]
    [ProducesResponseType(typeof(ApiError), 401)]
    [ProducesResponseType(typeof(ApiError), 404)]
    [ProducesResponseType(typeof(ApiError), 500)]
    public async Task<IActionResult> ResetAdminPassword([FromBody] ResetAdminPasswordRequest request)
    {
        try
        {
            var newPassword = await _adService.ResetAdminPasswordAsync(User, request);
            return Ok(new { SamAccountName = $"{request.SamAccountName}-a", NewPassword = newPassword });
        }
        catch (InvalidOperationException ioex)
        {
            return Unauthorized(new ApiError("Permission denied.", ioex.Message));
        }
        catch (KeyNotFoundException knfex)
        {
            return NotFound(new ApiError(knfex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while resetting admin password for '{SamAccountName}'.", request.SamAccountName);
            return StatusCode(500, new ApiError("An unexpected server error occurred.", ex.Message));
        }
    }

    /// <summary>
    /// Unlocks a user's account if it is locked out.
    /// </summary>
    [HttpPost("unlock")]
    [ProducesResponseType(204)]
    [ProducesResponseType(typeof(ApiError), 404)]
    [ProducesResponseType(typeof(ApiError), 500)]
    public async Task<IActionResult> UnlockAccount([FromBody] UserActionRequest request)
    {
        try
        {
            await _adService.UnlockAccountAsync(request);
            return NoContent();
        }
        catch (KeyNotFoundException knfex)
        {
            return NotFound(new ApiError(knfex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while unlocking account for '{SamAccountName}'.", request.SamAccountName);
            return StatusCode(500, new ApiError("An unexpected server error occurred.", ex.Message));
        }
    }

    /// <summary>
    /// Disables a user's account.
    /// </summary>
    [HttpPost("disable")]
    [ProducesResponseType(204)]
    [ProducesResponseType(typeof(ApiError), 404)]
    [ProducesResponseType(typeof(ApiError), 500)]
    public async Task<IActionResult> DisableAccount([FromBody] UserActionRequest request)
    {
        try
        {
            await _adService.DisableAccountAsync(request);
            return NoContent();
        }
        catch (KeyNotFoundException knfex)
        {
            return NotFound(new ApiError(knfex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while disabling account for '{SamAccountName}'.", request.SamAccountName);
            return StatusCode(500, new ApiError("An unexpected server error occurred.", ex.Message));
        }
    }
    
    /// <summary>
    /// Enables a user's account.
    /// </summary>
    [HttpPost("enable")]
    [ProducesResponseType(204)]
    [ProducesResponseType(typeof(ApiError), 404)]
    [ProducesResponseType(typeof(ApiError), 500)]
    public async Task<IActionResult> EnableAccount([FromBody] UserActionRequest request)
    {
        try
        {
            await _adService.EnableAccountAsync(request);
            return NoContent();
        }
        catch (KeyNotFoundException knfex)
        {
            return NotFound(new ApiError(knfex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while enabling account for '{SamAccountName}'.", request.SamAccountName);
            return StatusCode(500, new ApiError("An unexpected server error occurred.", ex.Message));
        }
    }
}

