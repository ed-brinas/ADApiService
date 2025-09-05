using ADApiService.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.DirectoryServices.AccountManagement;

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
            
            var userGroups = new List<string>();
            // This logic requires System.DirectoryServices.AccountManagement
            // It resolves the user's group SIDs to their sAMAccountNames
            foreach (var claim in User.FindAll(ClaimTypes.GroupSid))
            {
                try
                {
                    using var context = new PrincipalContext(ContextType.Domain);
                    var group = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, claim.Value);
                    if (group != null)
                    {
                        if (!string.IsNullOrEmpty(group.SamAccountName))
                        {
                            userGroups.Add(group.SamAccountName);
                        }
                        group.Dispose();
                    }
                }
                catch
                {
                    // Ignore groups that can't be resolved
                }
            }

            var isHighPrivilege = _adSettings.HighPrivilegeGroups.Any(g => userGroups.Contains(g, StringComparer.OrdinalIgnoreCase));
            var canCreateUsers = isHighPrivilege || _adSettings.GeneralAccessGroups.Any(g => userGroups.Contains(g, StringComparer.OrdinalIgnoreCase));

            var userModel = new
            {
                Name = User.Identity.Name,
                IsHighPrivilege = isHighPrivilege,
                CanCreateUsers = canCreateUsers,
                Groups = userGroups
            };

            return Ok(userModel);
        }
    }
}

