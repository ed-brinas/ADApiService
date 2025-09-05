using ADApiService.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;

namespace ADApiService.Controllers;

/// <summary>
/// Provides endpoints for user authentication and context.
/// </summary>
[Route("api/[controller]")]
[ApiController]
[Authorize] // All methods in this controller require authentication
public class AuthController : ControllerBase
{
    private readonly AdSettings _adSettings;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IOptions<AdSettings> adSettings, ILogger<AuthController> logger)
    {
        _adSettings = adSettings.Value;
        _logger = logger;
    }

    /// <summary>
    /// Gets the current authenticated user's context, including their permissions.
    /// </summary>
    /// <returns>The user's context information.</returns>
    [HttpGet("me")]
    [ProducesResponseType(typeof(UserContextModel), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult GetCurrentUser()
    {
        if (User.Identity?.IsAuthenticated != true || string.IsNullOrEmpty(User.Identity.Name))
        {
            return Unauthorized();
        }

        var userGroups = GetUserGroupNames(User);
        
        var isHighPrivilege = _adSettings.AccessControl.HighPrivilegeGroups.Any(g => userGroups.Contains(g, StringComparer.OrdinalIgnoreCase));
        var hasGeneralAccess = _adSettings.AccessControl.GeneralAccessGroups.Any(g => userGroups.Contains(g, StringComparer.OrdinalIgnoreCase));

        // A user can create other users if they are in EITHER the high privilege OR general access groups.
        var canCreateUsers = isHighPrivilege || hasGeneralAccess;
        
        var userModel = new UserContextModel
        {
            Name = User.Identity.Name,
            IsHighPrivilege = isHighPrivilege,
            CanCreateUsers = canCreateUsers,
            Groups = userGroups
        };

        return Ok(userModel);
    }
    
    private List<string> GetUserGroupNames(ClaimsPrincipal user)
    {
        var groupNames = new List<string>();
        var groupSids = user.FindAll(ClaimTypes.GroupSid).Select(c => c.Value);

        try
        {
            // Use the forest root to resolve SIDs from any domain in the forest
            using var context = new PrincipalContext(ContextType.Domain, _adSettings.ForestRootDomain);
            foreach (var sid in groupSids)
            {
                try
                {
                    var group = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, sid);
                    if (group?.SamAccountName != null)
                    {
                        groupNames.Add(group.SamAccountName);
                    }
                }
                catch (Exception ex)
                {
                    // This is often normal for well-known SIDs that don't resolve to a group object (e.g., "Everyone")
                    _logger.LogTrace(ex, "Could not resolve SID {Sid} to a group name.", sid);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Fatal error connecting to forest root domain '{Domain}' to resolve group SIDs. User permissions may be incorrect.", _adSettings.ForestRootDomain);
        }
        
        return groupNames;
    }
}

