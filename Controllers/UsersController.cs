using ADApiService.Models; // <-- THIS LINE IS THE FIX
using ADApiService.Services;
using Microsoft.AspNetCore.Mvc;

namespace ADApiService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IAdService _adService;

        public UsersController(IAdService adService)
        {
            _adService = adService;
        }

        [HttpPost("create")]
        public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request) // This line needs the fix
        {
            try
            {
                var result = await _adService.CreateUserAsync(User, request);
                if (!result)
                {
                    return BadRequest(new ApiError("User creation failed. The user may already exist or input is invalid."));
                }
                return Ok(new { message = "User created successfully." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new ApiError("An unexpected error occurred during user creation.", ex.Message));
            }
        }
        
        // ... other methods in this controller will also need the 'using' statement ...
        [HttpPut("update")]
        public async Task<IActionResult> UpdateUser([FromBody] UpdateUserRequest request)
        {
            try
            {
                var success = await _adService.UpdateUserAsync(User, request);
                if (!success)
                {
                    return BadRequest(new ApiError("Failed to update user. See logs for details."));
                }
                return NoContent(); // Success
            }
            catch (Exception ex)
            {
                return StatusCode(500, new ApiError("An error occurred while updating the user.", ex.Message));
            }
        }

        [HttpGet("details/{domain}/{samAccountName}")]
        public async Task<IActionResult> GetUserDetails(string domain, string samAccountName)
        {
            try
            {
                var userDetails = await _adService.GetUserDetailsAsync(domain, samAccountName);
                if (userDetails == null)
                {
                    return NotFound(new ApiError("User not found."));
                }
                return Ok(userDetails);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new ApiError("An error occurred while fetching user details.", ex.Message));
            }
        }

        [HttpGet("list")]
        public async Task<IActionResult> ListUsers([FromQuery] string domain, [FromQuery] string? nameFilter, [FromQuery] bool? statusFilter)
        {
            try
            {
                var users = await _adService.ListUsersAsync(domain, nameFilter, statusFilter);
                return Ok(users);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new ApiError("An error occurred while listing users.", ex.Message));
            }
        }
    }
}

