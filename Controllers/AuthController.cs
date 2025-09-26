using KeyStone.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.DirectoryServices.AccountManagement;

namespace KeyStone.Controllers;

/// <summary>
/// Handles user authentication and provides user context.
/// </summary>
[Route("[controller]")]
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
        
        _logger.LogDebug("Found {Count} Group SIDs in user's token.", groupSids.Count);

        var unresolvedSids = new HashSet<string>(groupSids);

        // FIX: Iterate through each configured domain instead of using ContextType.Forest
        foreach (var domain in _adSettings.Domains)
        {
            if (!unresolvedSids.Any()) break; // Optimization: Stop if all SIDs have been resolved.

            try
            {
                _logger.LogDebug("Attempting to resolve SIDs against domain: {Domain}", domain);
                using var context = new PrincipalContext(ContextType.Domain, domain);
                var sidsInThisDomain = unresolvedSids.ToList(); // Create a copy to iterate over

                foreach (var sid in sidsInThisDomain)
                {
                    try
                    {
                        var group = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, sid);
                        if (group?.SamAccountName != null)
                        {
                            userGroups.Add(group.SamAccountName);
                            unresolvedSids.Remove(sid); // Mark SID as resolved
                            _logger.LogInformation("SUCCESS: Resolved SID {Sid} to Group Name: {GroupName} in domain {Domain}", sid, group.SamAccountName, domain);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogTrace(ex, "Could not resolve SID {Sid} in domain {Domain}. This is expected if the group belongs to another domain.", sid, domain);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "CRITICAL_FAILURE: Could not connect to PrincipalContext for domain '{Domain}'. Check service account permissions and network connectivity.", domain);
                // Continue to the next domain rather than failing the entire request.
            }
        }

        if (unresolvedSids.Any())
        {
            _logger.LogWarning("Could not resolve {Count} SIDs: {SIDs}", unresolvedSids.Count, string.Join(", ", unresolvedSids));
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

