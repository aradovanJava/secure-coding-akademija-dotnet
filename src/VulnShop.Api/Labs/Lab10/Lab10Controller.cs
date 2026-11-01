using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab10;

/// <summary>
/// Lab10 – A06 Insecure Design: poslovna logika (CWE-840, CWE-20).
///
/// ISPRAVLJENO (pravila poslovne logike provodi POSLUŽITELJ):
///  - cijena se uzima iz baze (<c>lab10_products</c>), a <c>unitPrice</c> iz zahtjeva se ignorira,
///  - količina 1..10, barem jedna stavka, poznati proizvodi,
///  - najviše jedan kupon po narudžbi i jednokratna uporaba kupona po korisniku,
///  - ukupni iznos mora biti &gt; 0 i pokriven stanjem novčanika,
///  - terećenje, zapis o kuponu i provjere izvode se u jednoj transakciji.
/// </summary>
[ApiController]
[Route("api/lab10")]
[RequireAuth]
public sealed class Lab10Controller(Db db) : ControllerBase
{
    private const string Coupon = "AKADEMIJA10";
    private const decimal CouponFactor = 0.90m;

    /// <summary>ISPRAVLJENO: klijent šalje samo proizvod i količinu (eventualni unitPrice se ignorira).</summary>
    public sealed record CheckoutItem(long ProductId, int Quantity);

    public sealed record CheckoutRequest(List<CheckoutItem>? Items, List<string>? CouponCodes);

    [HttpGet("wallet")]
    public IActionResult Wallet()
    {
        var user = HttpContext.RequireCurrentUser();
        var balance = Money.Parse(db.Scalar("SELECT balance FROM lab10_wallets WHERE username = $u", ("$u", user.Username)));
        return Ok(new { username = user.Username, balance });
    }

    [HttpPost("checkout")]
    public IActionResult Checkout([FromBody] CheckoutRequest request)
    {
        var user = HttpContext.RequireCurrentUser();
        var items = request.Items ?? new List<CheckoutItem>();
        var coupons = request.CouponCodes ?? new List<string>();

        // ISPRAVLJENO: validacija ulaza prije bilo kakve promjene stanja.
        if (items.Count is < 1 or > 20 || items.Any(i => i.Quantity is < 1 or > 10))
        {
            return BadRequest(new { error = "Narudžba mora imati 1–20 stavki, a količina mora biti 1–10." });
        }
        if (coupons.Count > 1)
        {
            return BadRequest(new { error = "Dopušten je najviše jedan kupon po narudžbi." });
        }
        if (coupons.Count == 1 && !string.Equals(coupons[0], Coupon, StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new { error = "Nepoznat kupon." });
        }

        return db.Use<IActionResult>(conn =>
        {
            using var tx = conn.BeginTransaction();

            // ISPRAVLJENO: cijene iz baze, ne iz zahtjeva.
            var total = 0m;
            foreach (var item in items)
            {
                var product = Db.QueryIn(conn, tx, "SELECT price FROM lab10_products WHERE id = $id", ("$id", item.ProductId));
                if (product.Count == 0)
                {
                    return BadRequest(new { error = "Nepoznat proizvod." });
                }
                total += product[0].GetDecimal("price") * item.Quantity;
            }

            if (coupons.Count == 1)
            {
                // ISPRAVLJENO: kupon se smije iskoristiti samo jednom po korisniku.
                var used = Db.QueryIn(conn, tx,
                    "SELECT 1 FROM lab10_coupon_usage WHERE username = $u AND coupon = $c",
                    ("$u", user.Username), ("$c", Coupon));
                if (used.Count > 0)
                {
                    return BadRequest(new { error = "Kupon je već iskorišten." });
                }
                Db.ExecuteIn(conn, tx, "INSERT INTO lab10_coupon_usage (username, coupon) VALUES ($u, $c)",
                    ("$u", user.Username), ("$c", Coupon));
                total *= CouponFactor;
            }
            total = Math.Round(total, 2, MidpointRounding.AwayFromZero);

            var balance = Db.QueryIn(conn, tx, "SELECT balance FROM lab10_wallets WHERE username = $u", ("$u", user.Username))[0]
                .GetDecimal("balance");
            if (total <= 0 || total > balance)
            {
                return BadRequest(new { error = "Iznos nije valjan ili stanje novčanika nije dostatno." });
            }

            var newBalance = balance - total;
            Db.ExecuteIn(conn, tx, "UPDATE lab10_wallets SET balance = $b WHERE username = $u",
                ("$b", Money.ToDb(newBalance)), ("$u", user.Username));
            tx.Commit();
            return Ok(new { charged = total, balance = newBalance });
        });
    }
}
