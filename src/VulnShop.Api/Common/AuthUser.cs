namespace VulnShop.Api.Common;

/// <summary>Prijavljeni korisnik (iz tablice <c>users</c>).</summary>
public sealed record AuthUser(long Id, string Username, string Role)
{
    public bool IsAdmin => string.Equals(Role, "ADMIN", StringComparison.Ordinal);
}
