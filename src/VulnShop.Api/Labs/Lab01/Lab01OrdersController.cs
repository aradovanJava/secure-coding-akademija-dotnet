using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab01;

/// <summary>
/// Lab01 – A01 Broken Access Control: IDOR (CWE-639).
///
/// ISPRAVLJENO: nakon dohvata narudžbe provjerava se vlasništvo. Korisnik koji nije vlasnik
/// (i nije ADMIN) dobiva 404 – isto kao da narudžba ne postoji, kako se ne bi otkrivalo
/// koji identifikatori postoje.
/// </summary>
[ApiController]
[Route("api/lab01")]
[RequireAuth]
public sealed class Lab01OrdersController(Db db) : ControllerBase
{
    [HttpGet("orders/{id:long}")]
    public IActionResult GetOrder(long id)
    {
        var user = HttpContext.RequireCurrentUser();
        var rows = db.Query(
            "SELECT id, owner_username, items, shipping_address, total FROM lab01_orders WHERE id = $id",
            ("$id", id));

        // ISPRAVLJENO: provjera vlasništva na poslužitelju (ADMIN smije sve).
        // Tuđa narudžba → 404, jednako kao nepostojeća (ne otkrivamo postojanje).
        if (rows.Count == 0 || (rows[0].GetString("owner_username") != user.Username && !user.IsAdmin))
        {
            return NotFound(new { error = "Narudžba nije pronađena." });
        }

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
