using Microsoft.AspNetCore.Identity;

namespace VulnShop.Api.Common;

/// <summary>
/// Pristup zajedničkoj tablici <c>users</c>. Lozinke su pohranjene sigurno pomoću
/// <see cref="PasswordHasher{TUser}"/> (PBKDF2 s nasumičnom soli). Nije dio vježbi.
/// </summary>
public sealed class UserService(Db db)
{
    private static readonly PasswordHasher<AuthUser> Hasher = new();

    public static string HashPassword(string password) => Hasher.HashPassword(null!, password);

    /// <summary>Vraća korisnika ako su korisničko ime i lozinka ispravni, inače <c>null</c>.</summary>
    public AuthUser? VerifyCredentials(string? username, string? password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            return null;
        }

        var rows = db.Query(
            "SELECT id, username, password_hash, role FROM users WHERE username = $u",
            ("$u", username));
        if (rows.Count == 0)
        {
            return null;
        }

        var row = rows[0];
        var user = new AuthUser(row.GetInt64("id"), row.GetString("username"), row.GetString("role"));
        var result = Hasher.VerifyHashedPassword(user, row.GetString("password_hash"), password);
        return result == PasswordVerificationResult.Failed ? null : user;
    }
}
