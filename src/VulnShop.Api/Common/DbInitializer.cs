using VulnShop.Api.Labs.Lab06;

namespace VulnShop.Api.Common;

/// <summary>
/// Stvara shemu i puni bazu početnim (seed) podacima pri svakom pokretanju aplikacije.
/// Baza je in-memory, pa svaka instanca aplikacije (i svaki test s vlastitom
/// WebApplicationFactory) kreće od istog, poznatog stanja.
///
/// Svaka vježba ima vlastite tablice s prefiksom <c>labXX_</c> radi izolacije.
/// Novčani iznosi pohranjuju se kao TEXT ("1000.00") i obrađuju kao <see cref="decimal"/>.
/// </summary>
public static class DbInitializer
{
    public static void Initialize(Db db)
    {
        db.Run(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = Schema;
            cmd.ExecuteNonQuery();
        });

        SeedUsers(db);
        SeedLab01(db);
        SeedLab02(db);
        SeedLab06(db);
        SeedLab07(db);
        SeedLab10(db);
        SeedLab11(db);
        SeedLab15(db);
    }

    private const string Schema = """
        -- Zajednička tablica korisnika (autentikacija). Lozinke: PasswordHasher (PBKDF2).
        CREATE TABLE users (
            id            INTEGER PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL
        );

        -- Lab01 – IDOR: narudžbe.
        CREATE TABLE lab01_orders (
            id               INTEGER PRIMARY KEY,
            owner_username   TEXT NOT NULL,
            items            TEXT NOT NULL,
            shipping_address TEXT NOT NULL,
            total            TEXT NOT NULL
        );

        -- Lab02 – Mass assignment: profili (uloga u profilu određuje pristup admin/users).
        CREATE TABLE lab02_profiles (
            user_id      INTEGER PRIMARY KEY,
            display_name TEXT NOT NULL,
            email        TEXT NOT NULL,
            role         TEXT NOT NULL
        );

        -- Lab06 – Kriptografski propusti: dio A (kupci) i dio B (kartice).
        CREATE TABLE lab06_customers (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE lab06_cards (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            owner      TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            last4      TEXT NOT NULL
        );

        -- Lab07 – SQL injection: proizvodi i računi (lozinke NAMJERNO u čistom tekstu).
        CREATE TABLE lab07_products (
            id          INTEGER PRIMARY KEY,
            name        TEXT NOT NULL,
            description TEXT NOT NULL,
            price       TEXT NOT NULL,
            hidden      INTEGER NOT NULL
        );
        CREATE TABLE lab07_accounts (
            id       INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );

        -- Lab08 – XSS: pohranjene recenzije.
        CREATE TABLE lab08_reviews (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            author     TEXT NOT NULL,
            text       TEXT NOT NULL
        );

        -- Lab10 – Poslovna logika: novčanici, proizvodi, iskorišteni kuponi.
        CREATE TABLE lab10_wallets (
            username TEXT PRIMARY KEY,
            balance  TEXT NOT NULL
        );
        CREATE TABLE lab10_products (
            id    INTEGER PRIMARY KEY,
            name  TEXT NOT NULL,
            price TEXT NOT NULL
        );
        CREATE TABLE lab10_coupon_usage (
            username TEXT NOT NULL,
            coupon   TEXT NOT NULL
        );

        -- Lab11 – Autentikacijski propusti: brute force / enumeracija.
        CREATE TABLE lab11_users (
            id            INTEGER PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );

        -- Lab15 – Rukovanje iznimkama: bankovni računi.
        CREATE TABLE lab15_accounts (
            account_no     TEXT PRIMARY KEY,
            owner_username TEXT NOT NULL,
            balance        TEXT NOT NULL
        );
        """;

    private static void SeedUsers(Db db)
    {
        InsertUser(db, 1, "ana", "Ana123!", "USER");
        InsertUser(db, 2, "marko", "Marko123!", "USER");
        InsertUser(db, 3, "admin", "Admin123!", "ADMIN");
    }

    private static void InsertUser(Db db, long id, string username, string password, string role) =>
        db.Execute(
            "INSERT INTO users (id, username, password_hash, role) VALUES ($id, $u, $h, $r)",
            ("$id", id), ("$u", username), ("$h", UserService.HashPassword(password)), ("$r", role));

    private static void SeedLab01(Db db)
    {
        const string sql = "INSERT INTO lab01_orders (id, owner_username, items, shipping_address, total) VALUES ($id, $o, $i, $a, $t)";
        db.Execute(sql, ("$id", 1001), ("$o", "ana"), ("$i", "Laptop, Miš"), ("$a", "Ilica 1, Zagreb"), ("$t", "999.00"));
        db.Execute(sql, ("$id", 1002), ("$o", "ana"), ("$i", "Tipkovnica"), ("$a", "Ilica 1, Zagreb"), ("$t", "49.00"));
        db.Execute(sql, ("$id", 1003), ("$o", "marko"), ("$i", "Monitor"), ("$a", "Savska 10, Zagreb"), ("$t", "299.00"));
        db.Execute(sql, ("$id", 1004), ("$o", "admin"), ("$i", "Server"), ("$a", "Koturaška 47, Zagreb"), ("$t", "4999.00"));
    }

    private static void SeedLab02(Db db)
    {
        const string sql = "INSERT INTO lab02_profiles (user_id, display_name, email, role) VALUES ($id, $d, $e, $r)";
        db.Execute(sql, ("$id", 1), ("$d", "Ana Anić"), ("$e", "ana@akademija.hr"), ("$r", "USER"));
        db.Execute(sql, ("$id", 2), ("$d", "Marko Marić"), ("$e", "marko@akademija.hr"), ("$r", "USER"));
        db.Execute(sql, ("$id", 3), ("$d", "Administrator"), ("$e", "admin@akademija.hr"), ("$r", "ADMIN"));
    }

    private static void SeedLab06(Db db)
    {
        // Kupci sa slabim lozinkama. ivan i maja imaju ISTU lozinku (123456).
        // Hash se računa metodom iz Lab06Passwords (na grani main: MD5 bez soli).
        foreach (var (username, password) in new[]
                 { ("ivan", "123456"), ("petra", "password"), ("luka", "qwerty"), ("maja", "123456") })
        {
            db.Execute(
                "INSERT INTO lab06_customers (username, password_hash) VALUES ($u, $h)",
                ("$u", username), ("$h", Lab06Passwords.Hash(password)));
        }
    }

    private static void SeedLab07(Db db)
    {
        const string sql = "INSERT INTO lab07_products (id, name, description, price, hidden) VALUES ($id, $n, $d, $p, $h)";
        db.Execute(sql, ("$id", 1), ("$n", "Laptop"), ("$d", "Prijenosno računalo"), ("$p", "899.00"), ("$h", 0));
        db.Execute(sql, ("$id", 2), ("$n", "Miš"), ("$d", "Optički miš"), ("$p", "19.00"), ("$h", 0));
        db.Execute(sql, ("$id", 3), ("$n", "Tipkovnica"), ("$d", "Mehanička tipkovnica"), ("$p", "79.00"), ("$h", 0));
        db.Execute(sql, ("$id", 4), ("$n", "Monitor"), ("$d", "27-inčni monitor"), ("$p", "299.00"), ("$h", 0));
        db.Execute(sql, ("$id", 5), ("$n", "Interni prototip X"), ("$d", "Tajni interni proizvod"), ("$p", "0.00"), ("$h", 1));

        // Računi s lozinkama u čistom tekstu (NAMJERNO, meta UNION napada).
        db.Execute("INSERT INTO lab07_accounts (id, username, password) VALUES (1, 'admin', 'SuperTajna2026')");
        db.Execute("INSERT INTO lab07_accounts (id, username, password) VALUES (2, 'webshop', 'Shop!2026')");
    }

    private static void SeedLab10(Db db)
    {
        foreach (var username in new[] { "ana", "marko", "admin" })
        {
            db.Execute("INSERT INTO lab10_wallets (username, balance) VALUES ($u, '1000.00')", ("$u", username));
        }
        db.Execute("INSERT INTO lab10_products (id, name, price) VALUES (1, 'Laptop', '899.00')");
        db.Execute("INSERT INTO lab10_products (id, name, price) VALUES (2, 'Slušalice', '99.00')");
        db.Execute("INSERT INTO lab10_products (id, name, price) VALUES (3, 'Kabel', '9.99')");
    }

    private static void SeedLab11(Db db)
    {
        // Lozinka sunshine1 nalazi se u wordlists/top-100.txt (demonstracija brute force napada).
        InsertLab11User(db, 1, "ivana", "sunshine1");
        InsertLab11User(db, 2, "tomislav", "T0m!slav#2026");
        // Zaseban korisnik za test zaključavanja računa (lockout).
        InsertLab11User(db, 3, "lockme", "Lock!Me2026");
    }

    private static void InsertLab11User(Db db, long id, string username, string password) =>
        db.Execute(
            "INSERT INTO lab11_users (id, username, password_hash) VALUES ($id, $u, $h)",
            ("$id", id), ("$u", username), ("$h", UserService.HashPassword(password)));

    private static void SeedLab15(Db db)
    {
        const string sql = "INSERT INTO lab15_accounts (account_no, owner_username, balance) VALUES ($a, $o, $b)";
        db.Execute(sql, ("$a", "HR-ANA-001"), ("$o", "ana"), ("$b", "5000.00"));
        db.Execute(sql, ("$a", "HR-MARKO-001"), ("$o", "marko"), ("$b", "1000.00"));
        db.Execute(sql, ("$a", "HR-ADMIN-001"), ("$o", "admin"), ("$b", "10000.00"));
    }
}
