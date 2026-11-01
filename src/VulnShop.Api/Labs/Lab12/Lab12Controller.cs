using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab12;

/// <summary>
/// Lab12 – A07 Authentication Failures: JWT propusti (CWE-347, CWE-798, CWE-613).
///
/// Prijava izdaje JWT (HS256) koji izrađuje <see cref="JwtService"/>. Endpointi <c>/me</c> i
/// <c>/admin</c> vjeruju claimovima iz tokena koje je <see cref="JwtService.Verify"/> prihvatio.
/// Ranjivosti su u <see cref="JwtService"/> (slaba tajna, alg:none, nema provjere exp).
/// </summary>
[ApiController]
[Route("api/lab12")]
public sealed class Lab12Controller(UserService users, JwtService jwt) : ControllerBase
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
        return Ok(new { token = jwt.CreateToken(user.Username, user.Role), tokenType = "Bearer" });
    }

    [HttpGet("me")]
    public IActionResult Me()
    {
        var token = ReadBearerToken();
        if (token is null)
        {
            return Unauthorized(new { error = "Neispravan ili nevažeći token." });
        }
        return Ok(new { sub = token.Subject, role = token.Role, exp = token.ExpiresAt });
    }

    [HttpGet("admin")]
    public IActionResult Admin()
    {
        var token = ReadBearerToken();
        if (token is null)
        {
            return Unauthorized(new { error = "Neispravan ili nevažeći token." });
        }
        if (token.Role != "ADMIN")
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "Potrebna je uloga ADMIN." });
        }
        return Ok(new { message = "Dobrodošli u administraciju, " + token.Subject + "!" });
    }

    private JwtService.VerifiedToken? ReadBearerToken()
    {
        var header = Request.Headers.Authorization.ToString();
        return header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? jwt.Verify(header["Bearer ".Length..].Trim())
            : null;
    }
}
