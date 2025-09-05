using ADApiService.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.DirectoryServices.AccountManagement;

namespace ADApiService.Controllers;

/// <summary>
/// Handles user authentication and provides user context.
/// </summary>
[Route("api/[controller]")]
[ApiController]
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
    /// Gets the context for the currently authenticated user.
    /// </summary>
    /// <returns>User context including name, permissions, and groups.</returns>
    [HttpGet("me")]
    public IActionResult GetCurrentUser()
    {
        if (User.Identity?.IsAuthenticated != true)
        {
            _logger.LogWarning("Authentication failed: User.Identity.IsAuthenticated is false.");
            return Unauthorized(new { Message = "User is not authenticated." });
        }
        
        _logger.LogInformation("--- Begin User Authorization Check for: {User} ---", User.Identity.Name);

        var userGroups = new List<string>();
        var groupSids = User.FindAll(ClaimTypes.GroupSid).Select(c => c.Value).ToList();
        
        _logger.LogDebug("Found {Count} Group SIDs in user's token: {SIDs}", groupSids.Count, string.Join(", ", groupSids));

        try
        {
            // FIX: Changed from ContextType.Domain to ContextType.Forest
            // This allows resolving SIDs from any domain in the forest via the Global Catalog.
            using var context = new PrincipalContext(ContextType.Forest, _adSettings.ForestRootDomain);
            _logger.LogDebug("Connecting to Forest Global Catalog '{Forest}' to resolve SIDs.", _adSettings.ForestRootDomain);

            foreach (var sid in groupSids)
            {
                try
                {
                    var group = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, sid);
                    if (group?.SamAccountName != null)
                    {
                        userGroups.Add(group.SamAccountName);
                        _logger.LogInformation("SUCCESS: Resolved SID {Sid} to Group Name: {GroupName}", sid, group.SamAccountName);
                    }
                    else
                    {
                         _logger.LogWarning("FAILURE: Could not resolve SID {Sid} to a group. It might be a well-known SID or from a different forest.", sid);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "ERROR: An exception occurred while trying to resolve SID {Sid}.", sid);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "CRITICAL_FAILURE: Could not connect to PrincipalContext for forest '{Forest}'. Check service account permissions and network connectivity to the domain controller.", _adSettings.ForestRootDomain);
            return StatusCode(500, new ApiError("Failed to contact Active Directory.", "Could not resolve user's group memberships."));
        }

        var isHighPrivilege = _adSettings.AccessControl.HighPrivilegeGroups.Any(g => userGroups.Contains(g, StringComparer.OrdinalIgnoreCase));
        var canCreateUsers = isHighPrivilege || _adSettings.AccessControl.GeneralAccessGroups.Any(g => userGroups.Contains(g, StringComparer.OrdinalIgnoreCase));

        _logger.LogInformation("Authorization check complete for {User}. IsHighPrivilege: {IsHighPrivilege}. CanCreateUsers: {CanCreate}", User.Identity.Name, isHighPrivilege, canCreateUsers);
        _logger.LogInformation("--- End User Authorization Check ---");

        if (!canCreateUsers)
        {
             return Unauthorized(new ApiError("Authorization Denied.", "Your account is not a member of any group authorized to use this application."));
        }
        
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

