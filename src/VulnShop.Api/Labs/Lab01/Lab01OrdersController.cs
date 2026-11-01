using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab01;

/// <summary>
/// Lab01 – A01 Broken Access Control: IDOR (CWE-639).
///
/// RANJIVO: narudžba se dohvaća samo po identifikatoru iz URL-a, bez provjere
/// pripada li prijavljenom korisniku. Svaki prijavljeni korisnik može pročitati
/// tuđu narudžbu (adresu dostave, stavke, iznos) jednostavnom promjenom broja u URL-u.
/// </summary>
[ApiController]
[Route("api/lab01")]
[RequireAuth]
public sealed class Lab01OrdersController(Db db) : ControllerBase
{
    [HttpGet("orders/{id:long}")]
    public IActionResult GetOrder(long id)
    {
        var rows = db.Query(
            "SELECT id, owner_username, items, shipping_address, total FROM lab01_orders WHERE id = $id",
            ("$id", id));
        if (rows.Count == 0)
        {
            return NotFound(new { error = "Narudžba nije pronađena." });
        }

        // RANJIVO: nema provjere vlasništva – vraća se narudžba bilo kojeg korisnika.
        var order = rows[0];
        return Ok(new
        {
            id = order.GetInt64("id"),
            owner = order.GetString("owner_username"),
            items = order.GetString("items"),
            shippingAddress = order.GetString("shipping_address"),
            total = order.GetDecimal("total"),
        });
    }
}
