namespace VulnShop.Api.Labs.Lab13;

/// <summary>Legitimna košarica koju klijent izvozi i ponovno uvozi.</summary>
public sealed class Cart
{
    public string? Owner { get; set; }
    public List<CartItem> Items { get; set; } = [];
}

/// <summary>Stavka košarice.</summary>
public sealed class CartItem
{
    public long ProductId { get; set; }
    public string? Name { get; set; }
    public int Quantity { get; set; }
}
