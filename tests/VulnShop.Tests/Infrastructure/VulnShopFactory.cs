using Microsoft.AspNetCore.Mvc.Testing;

namespace VulnShop.Tests.Infrastructure;

/// <summary>
/// Pokreće cijelu aplikaciju u memoriji (TestServer) za integracijske testove.
/// Svaka instanca tvornice ima SVOJU in-memory bazu (svjež seed), pa testovi
/// različitih klasa ne dijele stanje.
/// </summary>
public class VulnShopFactory : WebApplicationFactory<Program>
{
}
