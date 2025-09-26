using ADApiService.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;

namespace ADApiService.Controllers;

/// <summary>
/// Provides configuration settings to the frontend.
/// </summary>
[Route("api/[controller]")]
[ApiController]
[Authorize]
public class ConfigController : ControllerBase
{
    private readonly AdSettings _adSettings;
    private readonly ILogger<ConfigController> _logger;

    public ConfigController(IOptions<AdSettings> adSettings, ILogger<ConfigController> logger)
    {
        _adSettings = adSettings.Value;
        _logger = logger;
    }

    /// <summary>
    /// Gets configuration settings required by the frontend application.
    /// </summary>
    /// <remarks>
    /// This endpoint tailors the response based on the calling user's permissions.
    /// For example, the list of optional groups is only sent to high-privilege users.
    /// </remarks>
    /// <returns>A dynamic object containing configuration settings.</returns>
    [HttpGet("settings")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult GetSettings()
    {
        var isHighPrivilege = IsUserHighPrivilege(User);

        var settings = new
        {
            Domains = _adSettings.Domains,
            OptionalGroupsForHighPrivilege = isHighPrivilege ? _adSettings.Provisioning.OptionalGroupsForHighPrivilege : new List<string>()
        };

        return Ok(settings);
    }
    
    private bool IsUserHighPrivilege(ClaimsPrincipal callingUser)
    {
        // This helper method centralizes the logic for checking high-privilege status.
        var groupSids = callingUser.FindAll(ClaimTypes.GroupSid).Select(c => c.Value);
        try
        {
            using var context = new PrincipalContext(ContextType.Domain, _adSettings.ForestRootDomain);
            foreach (var sid in groupSids)
            {
                try
                {
                     var group = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, sid);
                     if (group != null && _adSettings.AccessControl.HighPrivilegeGroups.Contains(group.SamAccountName, StringComparer.OrdinalIgnoreCase))
                     {
                         return true;
                     }
                }
                catch (Exception ex)
                {
                    _logger.LogTrace(ex, "Could not resolve SID {Sid} to a group name.", sid);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error connecting to forest root domain '{Domain}' to determine user privilege.", _adSettings.ForestRootDomain);
        }
        return false;
    }
}

