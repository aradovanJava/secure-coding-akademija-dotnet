namespace VulnShop.Api.Common;

/// <summary>Dohvat trenutno prijavljenog korisnika iz <c>HttpContext.Items</c>.</summary>
public static class CurrentUserExtensions
{
    public const string ItemKey = "VulnShop.CurrentUser";

    public static AuthUser? GetCurrentUser(this HttpContext context) =>
        context.Items.TryGetValue(ItemKey, out var value) ? value as AuthUser : null;

    /// <summary>Za akcije označene s [RequireAuth] – korisnik sigurno postoji.</summary>
    public static AuthUser RequireCurrentUser(this HttpContext context) =>
        context.GetCurrentUser() ?? throw new InvalidOperationException("Korisnik nije prijavljen.");
}
