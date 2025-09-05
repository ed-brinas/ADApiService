using ADApiService.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;

namespace ADApiService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ConfigController : ControllerBase
    {
        private readonly AdSettings _adSettings;
        private readonly ILogger<ConfigController> _logger;

        public ConfigController(IOptions<AdSettings> adSettings, ILogger<ConfigController> logger)
        {
            _adSettings = adSettings.Value;
            _logger = logger;
        }

        [HttpGet("settings")]
        public IActionResult GetSettings()
        {
            // First, determine if the calling user is in a high-privilege group.
            var isHighPrivilege = false;
            try
            {
                var userGroupSids = User.FindAll(ClaimTypes.GroupSid).Select(c => c.Value);
                using var context = new PrincipalContext(ContextType.Domain, _adSettings.ForestRootDomain);

                foreach (var sid in userGroupSids)
                {
                    var group = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, sid);
                    if (group != null && _adSettings.AccessControl.HighPrivilegeGroups.Contains(group.SamAccountName, StringComparer.OrdinalIgnoreCase))
                    {
                        isHighPrivilege = true;
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to resolve user group memberships for settings endpoint.");
                // Fail securely - assume user is not high privilege if AD lookup fails.
                isHighPrivilege = false;
            }

            // Construct the settings object to return to the frontend.
            var settings = new
            {
                Domains = _adSettings.Domains,
                // Only send the list of optional groups if the user is privileged.
                // This line is corrected to use the proper property name.
                OptionalGroupsForHighPrivilege = isHighPrivilege ? _adSettings.Provisioning.OptionalGroupsForHighPrivilege : new List<string>()
            };

            return Ok(settings);
        }
    }
}

