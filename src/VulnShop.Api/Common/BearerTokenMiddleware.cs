namespace VulnShop.Api.Common;

/// <summary>
/// Čita zaglavlje <c>Authorization: Bearer &lt;token&gt;</c> i, ako je token valjan, postavlja
/// trenutnog korisnika u <c>HttpContext.Items</c>. Sam ne odbija zahtjeve – to radi
/// filtar <see cref="RequireAuthAttribute"/> na zaštićenim akcijama (401).
/// </summary>
public sealed class BearerTokenMiddleware(RequestDelegate next, TokenStore tokens)
{
    private const string Prefix = "Bearer ";

    public async Task InvokeAsync(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (header.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            var token = header[Prefix.Length..].Trim();
            if (tokens.TryGet(token, out var user) && user is not null)
            {
                context.Items[CurrentUserExtensions.ItemKey] = user;
            }
        }

        await next(context);
    }
}
