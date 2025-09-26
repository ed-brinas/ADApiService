using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KeyStone.Controllers
{
    /// <summary>
    /// Provides a simple endpoint to verify that the API is running.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class HealthCheckController : ControllerBase
    {
        /// <summary>
        /// Returns a success status if the API is operational.
        /// This endpoint does not require authentication.
        /// </summary>
        [AllowAnonymous] // This attribute overrides the global authentication policy.
        [HttpGet]
        public IActionResult Get()
        {
            return Ok(new 
            {
                Status = "OK",
                Timestamp = DateTime.UtcNow
            });
        }
    }
}
