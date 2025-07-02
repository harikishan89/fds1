using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

[ApiController]
[Route("api")]
public class AuthTestController : ControllerBase
{
    [HttpGet("public")]
    public IActionResult PublicEndpoint()
    {
        return Ok("🌍 This is a public endpoint.");
    }

    [HttpGet("secure")]
    public async Task<IActionResult> SecureEndpoint()
    {
        var token = Request.Headers["Authorization"].ToString();

        if (!token.StartsWith("Bearer "))
            return Unauthorized("Missing or invalid Authorization header.");

        token = token["Bearer ".Length..];

        try
        {
            var principal = await JwtValidator.ValidateTokenAsync(token);
            if (principal == null)
                return Unauthorized("Invalid token");

            var email = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
            return Ok(new { message = "✅ Token is valid!", user = email });
        }
        catch (Exception ex)
        {
            return Unauthorized($"❌ Token validation failed: {ex.Message}");
        }
    }
}
