using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab02;

/// <summary>
/// Lab02 – A01 Broken Access Control: mass assignment / eskalacija privilegija (CWE-915, CWE-269).
///
/// RANJIVO: <c>PUT /api/lab02/profile</c> veže (binda) CIJELI entitet profila iz JSON-a,
/// uključujući polje <c>role</c>, i zapisuje ga u bazu. Korisnik tako sam sebi može
/// postaviti ulogu ADMIN i dobiti pristup administratorskom endpointu.
/// </summary>
[ApiController]
[Route("api/lab02")]
[RequireAuth]
public sealed class Lab02ProfileController(Db db) : ControllerBase
{
    /// <summary>RANJIVO: entitet profila koristi se izravno kao ulazni model (uključuje i Role).</summary>
    public sealed class ProfileEntity
    {
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
        public string? Role { get; set; }
    }

    [HttpGet("profile")]
    public IActionResult GetProfile() => Ok(LoadProfile(HttpContext.RequireCurrentUser().Id));

    [HttpPut("profile")]
    public IActionResult UpdateProfile([FromBody] ProfileEntity profile)
    {
        var user = HttpContext.RequireCurrentUser();

        // RANJIVO: role dolazi izravno iz JSON-a i zapisuje se bez provjere (mass assignment).
        // Legitimni klijent ne šalje role (COALESCE zadržava postojeću vrijednost),
        // ali napadač može poslati "role":"ADMIN" i eskalirati privilegije.
        db.Execute(
            "UPDATE lab02_profiles SET display_name = COALESCE($d, display_name), email = COALESCE($e, email), " +
            "role = COALESCE($r, role) WHERE user_id = $id",
            ("$d", profile.DisplayName), ("$e", profile.Email), ("$r", profile.Role), ("$id", user.Id));

        return Ok(LoadProfile(user.Id));
    }

    [HttpGet("admin/users")]
    public IActionResult AdminUsers()
    {
        var user = HttpContext.RequireCurrentUser();

        // Ovlast se provjerava prema ulozi iz tablice profila (koju je napadač mogao promijeniti).
        var role = db.Scalar("SELECT role FROM lab02_profiles WHERE user_id = $id", ("$id", user.Id)) as string;
        if (role != "ADMIN")
        {
            return StatusCode(StatusCodes.Status403Forbidden,
                new { error = "Samo administrator smije vidjeti popis korisnika." });
        }

        var users = db.Query("SELECT user_id, display_name, email, role FROM lab02_profiles ORDER BY user_id")
            .Select(ToDto);
        return Ok(users);
    }

    private object LoadProfile(long userId) =>
        ToDto(db.Query(
            "SELECT user_id, display_name, email, role FROM lab02_profiles WHERE user_id = $id",
            ("$id", userId))[0]);

    private static object ToDto(Dictionary<string, object?> row) => new
    {
        userId = row.GetInt64("user_id"),
        displayName = row.GetString("display_name"),
        email = row.GetString("email"),
        role = row.GetString("role"),
    };
}
