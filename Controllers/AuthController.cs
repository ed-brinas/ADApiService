using ADApiService.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;

namespace ADApiService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AdSettings _adSettings;

        public AuthController(IOptions<AdSettings> adSettings)
        {
            _adSettings = adSettings.Value;
        }

        [HttpGet("me")]
        public IActionResult GetCurrentUser()
        {
            if (User.Identity?.IsAuthenticated != true)
            {
                return Unauthorized();
            }

            var userGroups = User.FindAll(ClaimTypes.GroupSid)
                .Select(s => s.Value)
                .ToList();

            var resolvedGroupNames = new List<string>();
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, _adSettings.ForestRootDomain);
                foreach (var sid in userGroups)
                {
                    var group = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, sid);
                    if (group != null && !string.IsNullOrEmpty(group.SamAccountName))
                    {
                        resolvedGroupNames.Add(group.SamAccountName);
                    }
                }
            }
            catch
            {
                // In case of issues connecting to AD, proceed with unresolved SIDs if necessary or log the error.
            }
            
            var isHighPrivilege = _adSettings.AccessControl.HighPrivilegeGroups.Any(g => resolvedGroupNames.Contains(g, StringComparer.OrdinalIgnoreCase));
            var canCreateUsers = isHighPrivilege || _adSettings.AccessControl.GeneralAccessGroups.Any(g => resolvedGroupNames.Contains(g, StringComparer.OrdinalIgnoreCase));

            return Ok(new
            {
                Name = User.Identity.Name,
                IsHighPrivilege = isHighPrivilege,
                CanCreateUsers = canCreateUsers,
                Groups = resolvedGroupNames
            });
        }
    }
}

