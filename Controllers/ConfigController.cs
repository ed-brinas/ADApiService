using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using ADApiService.Models;

namespace ADApiService.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ConfigController : ControllerBase
{
    private readonly AdSettings _adSettings;

    public ConfigController(IOptions<AdSettings> adSettings)
    {
        _adSettings = adSettings.Value;
    }

    [HttpGet("settings")]
    public ActionResult<object> GetPublicSettings()
    {
        var settings = new
        {
            Domains = _adSettings.Domains,
            OptionalGroups = _adSettings.Provisioning.OptionalUserGroups
        };
        return Ok(settings);
    }
}

