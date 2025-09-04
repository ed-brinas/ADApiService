using Microsoft.AspNetCore.Mvc;
using ADApiService.Services;
using ADApiService.Models;

namespace ADApiService.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAdService _adService;

    public AuthController(IAdService adService)
    {
        _adService = adService;
    }

    [HttpGet("me")]
    public ActionResult<UserContext> GetCurrentUserContext()
    {
        try
        {
            return Ok(_adService.GetUserContext(User));
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiError("Failed to retrieve user context", ex.Message));
        }
    }
}

