using ADApiService.Models;
using ADApiService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace ADApiService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    // Authorize all actions in this controller based on the "GeneralAccess" roles defined in appsettings.json
    [Authorize(Roles = "L2,L3,Domain Admins,Enterprise Admins")] 
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
        /// Creates a new standard user and, if the caller is privileged, a corresponding admin user.
        /// </summary>
        [HttpPost("create")]
        // Further restrict this endpoint to only users with account creation privileges.
        [Authorize(Roles = "L3,Domain Admins,Enterprise Admins")]
        [ProducesResponseType(typeof(object), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ApiError), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ApiError), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
        {
            try
            {
                var (standardUser, adminUser) = await _adService.CreateUserAsync(request, User);
                _logger.LogInformation("User creation request successful for '{SamAccountName}' by '{Requester}'", request.SamAccountName, User.Identity?.Name);
                
                return CreatedAtAction(nameof(ListUsers), new { domain = request.Domain, nameFilter = request.SamAccountName }, new { standardUser, adminUser });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new ApiError("Validation Error", ex.Message));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled error occurred while creating user '{SamAccountName}'", request.SamAccountName);
                return StatusCode(500, new ApiError("An internal server error occurred.", ex.Message));
            }
        }

        /// <summary>
        /// Retrieves a list of users with filtering options.
        /// </summary>
        [HttpGet("list")]
        [ProducesResponseType(typeof(IEnumerable<UserResponse>), StatusCodes.Status200OK)]
        public IActionResult ListUsers([FromQuery, Required] string domain, [FromQuery] string? groupFilter, [FromQuery] string? nameFilter, [FromQuery] bool? statusFilter)
        {
            try
            {
                var users = _adService.ListUsers(domain, groupFilter, nameFilter, statusFilter);
                return Ok(users);
            }
            catch (Exception ex)
            {
                 _logger.LogError(ex, "An unhandled error occurred while listing users for domain '{Domain}'", domain);
                return StatusCode(500, new ApiError("An internal server error occurred.", ex.Message));
            }
        }

        /// <summary>
        /// Resets a user's password and unlocks their account.
        /// </summary>
        [HttpPost("reset-password")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ApiError), StatusCodes.Status404NotFound)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            try
            {
                await _adService.ResetPasswordAsync(request);
                return NoContent();
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(new ApiError(ex.Message));
            }
            catch (Exception ex)
            {
                 _logger.LogError(ex, "An unhandled error occurred during password reset for '{SamAccountName}'", request.SamAccountName);
                return StatusCode(500, new ApiError("An internal server error occurred.", ex.Message));
            }
        }

        /// <summary>
        /// Unlocks a user's account.
        /// </summary>
        [HttpPost("unlock")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ApiError), StatusCodes.Status404NotFound)]
        public async Task<IActionResult> UnlockAccount([FromBody] UnlockAccountRequest request)
        {
            try
            {
                await _adService.UnlockAccountAsync(request);
                return NoContent();
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(new ApiError(ex.Message));
            }
            catch (Exception ex)
            {
                 _logger.LogError(ex, "An unhandled error occurred during account unlock for '{SamAccountName}'", request.SamAccountName);
                return StatusCode(500, new ApiError("An internal server error occurred.", ex.Message));
            }
        }
    }
}

