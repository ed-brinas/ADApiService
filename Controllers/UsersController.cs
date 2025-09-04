using Microsoft.AspNetCore.Mvc;
using ADApiService.Models;
using ADApiService.Services;

namespace ADApiService.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly IAdService _adService;
    private readonly ILogger<UsersController> _logger;

    public UsersController(IAdService adService, ILogger<UsersController> logger)
    {
        _adService = adService;
        _logger = logger;
    }

    [HttpPost("create")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        try
        {
            await _adService.CreateUserAsync(request, User);
            _logger.LogInformation("User '{SamAccountName}' created successfully by '{CallingUser}'.", request.SamAccountName, User.Identity!.Name);
            return Ok(new { message = $"User {request.SamAccountName} created successfully." });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating user '{SamAccountName}'.", request.SamAccountName);
            return StatusCode(500, new ApiError("User creation failed.", ex.Message));
        }
    }
    
    [HttpGet("list")]
    public async Task<ActionResult<IEnumerable<UserListItem>>> ListUsers([FromQuery] string domain, [FromQuery] string? nameFilter, [FromQuery] bool? statusFilter)
    {
        try
        {
            var users = await _adService.ListUsersAsync(domain, nameFilter, statusFilter);
            return Ok(users);
        }
        catch (Exception ex)
        {
             _logger.LogError(ex, "Error listing users in domain '{Domain}'.", domain);
            return StatusCode(500, new ApiError("Failed to list users.", ex.Message));
        }
    }

    [HttpPost("resetpassword")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        try
        {
            await _adService.ResetPasswordAsync(request.Domain, request.SamAccountName, request.NewPassword);
            return Ok(new { message = "Password reset successfully." });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiError("Password reset failed.", ex.Message));
        }
    }

    [HttpPost("unlock")]
    public async Task<IActionResult> UnlockAccount([FromBody] UnlockAccountRequest request)
    {
        try
        {
            await _adService.UnlockAccountAsync(request.Domain, request.SamAccountName);
            return Ok(new { message = "Account unlocked successfully." });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiError("Account unlock failed.", ex.Message));
        }
    }
}

public class UnlockAccountRequest
{
    public string Domain { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
}

