using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab10;

/// <summary>
/// Lab10 – A06 Insecure Design: poslovna logika (CWE-840, CWE-20).
///
/// RANJIVO: poslužitelj vjeruje cijeni (<c>unitPrice</c>) i količini (<c>quantity</c>) iz
/// zahtjeva (dopušta i negativne vrijednosti), primjenjuje SVAKI kupon iz liste (i isti više
/// puta) te mijenja stanje novčanika bez ikakve provjere. Negativna količina tako POVEĆAVA
/// stanje, a ponavljanjem kupona iznos se umjetno obara.
/// </summary>
[ApiController]
[Route("api/lab10")]
[RequireAuth]
public sealed class Lab10Controller(Db db) : ControllerBase
{
    public sealed record CheckoutItem(long ProductId, int Quantity, decimal UnitPrice);

    public sealed record CheckoutRequest(List<CheckoutItem>? Items, List<string>? CouponCodes);

    [HttpGet("wallet")]
    public IActionResult Wallet()
    {
        var user = HttpContext.RequireCurrentUser();
        return Ok(new { username = user.Username, balance = GetBalance(user.Username) });
    }

    [HttpPost("checkout")]
    public IActionResult Checkout([FromBody] CheckoutRequest request)
    {
        var user = HttpContext.RequireCurrentUser();

        // RANJIVO: koriste se unitPrice i quantity iz zahtjeva (bez provjere predznaka i raspona).
        var total = 0m;
        foreach (var item in request.Items ?? new List<CheckoutItem>())
        {
            total += item.UnitPrice * item.Quantity;
        }

        // RANJIVO: svaki kupon iz liste primjenjuje se zasebno (može i više puta isti).
        foreach (var coupon in request.CouponCodes ?? new List<string>())
        {
            if (string.Equals(coupon, "AKADEMIJA10", StringComparison.OrdinalIgnoreCase))
            {
                total *= 0.90m;
            }
        }
        total = Math.Round(total, 2, MidpointRounding.AwayFromZero);

        // RANJIVO: nema provjere total > 0 ni dostatnog stanja; negativan total povećava stanje.
        var newBalance = GetBalance(user.Username) - total;
        db.Execute("UPDATE lab10_wallets SET balance = $b WHERE username = $u",
            ("$b", Money.ToDb(newBalance)), ("$u", user.Username));

        return Ok(new { charged = total, balance = newBalance });
    }

    private decimal GetBalance(string username) =>
        Money.Parse(db.Scalar("SELECT balance FROM lab10_wallets WHERE username = $u", ("$u", username)));
}
