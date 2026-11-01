using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab02;

/// <summary>
/// Lab02 – A01 Broken Access Control: mass assignment / eskalacija privilegija (CWE-915, CWE-269).
///
/// ISPRAVLJENO: <c>PUT /api/lab02/profile</c> prima zaseban DTO (<see cref="ProfileUpdateRequest"/>)
/// koji sadrži SAMO polja koja korisnik smije mijenjati (displayName, email), uz validaciju
/// (DataAnnotations). Polje <c>role</c> iz JSON-a se ignorira – uloga se mijenja isključivo
/// kroz administratorski proces.
/// </summary>
[ApiController]
[Route("api/lab02")]
[RequireAuth]
public sealed class Lab02ProfileController(Db db) : ControllerBase
{
    /// <summary>ISPRAVLJENO: ulazni DTO bez polja Role (allowlista dopuštenih polja).</summary>
    public sealed class ProfileUpdateRequest
    {
        [Required, StringLength(100, MinimumLength = 1)]
        public string? DisplayName { get; set; }

        [Required, EmailAddress, StringLength(200)]
        public string? Email { get; set; }
    }

    [HttpGet("profile")]
    public IActionResult GetProfile() => Ok(LoadProfile(HttpContext.RequireCurrentUser().Id));

    [HttpPut("profile")]
    public IActionResult UpdateProfile([FromBody] ProfileUpdateRequest request)
    {
        // [ApiController] automatski vraća 400 ako validacija (DataAnnotations) ne prođe.
        var user = HttpContext.RequireCurrentUser();

        // ISPRAVLJENO: ažuriraju se samo dopuštena polja; stupac role se NE dira.
        db.Execute(
            "UPDATE lab02_profiles SET display_name = $d, email = $e WHERE user_id = $id",
            ("$d", request.DisplayName), ("$e", request.Email), ("$id", user.Id));

        return Ok(LoadProfile(user.Id));
    }

    [HttpGet("admin/users")]
    public IActionResult AdminUsers()
    {
        var user = HttpContext.RequireCurrentUser();

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
