using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Common;

/// <summary>
/// Zajednička prijava: <c>POST /api/auth/login</c> → nasumični Bearer token.
/// Implementirano ISPRAVNO (nije dio vježbi).
/// </summary>
[ApiController]
[Route("api/auth")]
public sealed class AuthController(UserService users, TokenStore tokens) : ControllerBase
{
    public sealed record LoginRequest(string? Username, string? Password);

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var user = users.VerifyCredentials(request.Username, request.Password);
        if (user is null)
        {
            return Unauthorized(new { error = "Neispravno korisničko ime ili lozinka." });
        }

        var token = tokens.Issue(user);
        return Ok(new { token, username = user.Username, role = user.Role });
    }
}
