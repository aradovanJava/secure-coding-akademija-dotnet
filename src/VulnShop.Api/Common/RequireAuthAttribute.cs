using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace VulnShop.Api.Common;

/// <summary>
/// Označava akciju/kontroler kojem smije pristupiti samo prijavljeni korisnik.
/// Bez valjanog Bearer tokena vraća 401.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class RequireAuthAttribute : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (context.HttpContext.GetCurrentUser() is null)
        {
            context.Result = new UnauthorizedObjectResult(new { error = "Potrebna je prijava (Bearer token)." });
        }
    }
}
