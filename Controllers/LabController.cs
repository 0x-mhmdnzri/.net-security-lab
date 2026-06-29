using System.Net;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using Microsoft.Data.Sqlite;
using SecurityLab.Models;

namespace SecurityLab.Controllers;

public class LabController : Controller
{
    private static readonly object DbInitLock = new();
    private static bool DbInitialized;
    private static readonly string DbFilePath = Path.Combine(Environment.CurrentDirectory, "App_Data", "securitylab.db");
    private static readonly Dictionary<string, int> TransferBalances = new(StringComparer.OrdinalIgnoreCase)
    {
        ["alice"] = 500,
        ["bob"] = 250
    };

    private static readonly List<Document> Documents = new()
    {
        new(1, "Alice Invoice", "alice"),
        new(2, "Bob Salary Sheet", "bob")
    };

    private static readonly object BalanceLock = new();
    private static readonly HttpClient HttpClient = new();

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Xss(string? input, bool hardened = false)
    {
        ViewData["Input"] = input;
        ViewData["Hardened"] = hardened;
        return View();
    }

    public IActionResult OpenRedirect(string? returnUrl, bool hardened = false)
    {
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["Hardened"] = hardened;

        if (!string.IsNullOrWhiteSpace(returnUrl) && !hardened)
        {
            return Redirect(returnUrl);
        }

        if (!string.IsNullOrWhiteSpace(returnUrl) && hardened)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            ViewData["Error"] = "Redirect blocked: only local URLs are allowed in the hardened implementation.";
        }

        return View();
    }

    public IActionResult Clickjacking()
    {
        return View();
    }

    public IActionResult ClickjackingTarget(bool hardened = false)
    {
        if (hardened)
        {
            Response.Headers["X-Frame-Options"] = "DENY";
        }

        ViewData["Hardened"] = hardened;
        return View();
    }

    public IActionResult Csrf()
    {
        ViewData["Balances"] = TransferBalances;
        return View();
    }

    [HttpPost]
    public IActionResult Transfer(string from, string to, int amount)
    {
        if (!TransferBalances.ContainsKey(from) || !TransferBalances.ContainsKey(to))
        {
            ViewData["Message"] = "Invalid accounts.";
        }
        else if (TransferBalances[from] < amount)
        {
            ViewData["Message"] = "Insufficient funds.";
        }
        else
        {
            TransferBalances[from] -= amount;
            TransferBalances[to] += amount;
            ViewData["Message"] = $"Vulnerable transfer completed: {amount} from {from} to {to}.";
        }

        ViewData["Balances"] = TransferBalances;
        return View("Csrf");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult TransferSafe(string from, string to, int amount)
    {
        if (!TransferBalances.ContainsKey(from) || !TransferBalances.ContainsKey(to))
        {
            ViewData["Message"] = "Invalid accounts.";
        }
        else if (TransferBalances[from] < amount)
        {
            ViewData["Message"] = "Insufficient funds.";
        }
        else
        {
            TransferBalances[from] -= amount;
            TransferBalances[to] += amount;
            ViewData["Message"] = $"Protected transfer completed: {amount} from {from} to {to}.";
        }

        ViewData["Balances"] = TransferBalances;
        return View("Csrf");
    }

    public IActionResult Idor(int id = 1, string user = "alice", bool hardened = false)
    {
        ViewData["User"] = user;
        ViewData["RequestedId"] = id.ToString();
        ViewData["Hardened"] = hardened;

        var document = Documents.FirstOrDefault(d => d.Id == id);
        if (document is null)
        {
            ViewData["Error"] = "Document not found.";
            return View();
        }

        if (hardened && !string.Equals(document.Owner, user, StringComparison.OrdinalIgnoreCase))
        {
            ViewData["Error"] = "Access denied: this document is owned by another user.";
            return View();
        }

        ViewData["Document"] = document;
        return View();
    }

    public IActionResult SqlInjection(string? query, bool hardened = false)
    {
        EnsureDatabase();
        ViewData["Query"] = query;
        ViewData["Hardened"] = hardened;
        ViewData["Results"] = string.IsNullOrWhiteSpace(query) ? Array.Empty<Product>() : SearchProducts(query, hardened);
        return View();
    }

    public IActionResult RaceCondition(bool safe = false, int attempts = 5, int amount = 30)
    {
        var initialBalance = 100;
        var account = new BankAccount { Balance = initialBalance };
        var results = new List<RaceResult>();
        var tasks = new List<Task>();

        for (var index = 1; index <= attempts; index++)
        {
            var attempt = index;
            tasks.Add(Task.Run(() =>
            {
                var success = safe ? WithdrawSafe(account, amount) : WithdrawVulnerable(account, amount);
                lock (results)
                {
                    results.Add(new RaceResult($"Attempt {attempt}", success));
                }
            }));
        }

        Task.WaitAll(tasks.ToArray());

        ViewData["InitialBalance"] = initialBalance;
        ViewData["FinalBalance"] = account.Balance;
        ViewData["Results"] = results;
        ViewData["Safe"] = safe;
        ViewData["Attempts"] = attempts;
        ViewData["Amount"] = amount;
        return View();
    }

    public async Task<IActionResult> Ssrf(string? targetUrl, bool hardened = false)
    {
        ViewData["TargetUrl"] = targetUrl;
        ViewData["Hardened"] = hardened;

        if (!string.IsNullOrWhiteSpace(targetUrl))
        {
            if (hardened && !IsAllowedHost(targetUrl))
            {
                ViewData["Error"] = "Request blocked: the hardened fetch only allows local URLs.";
                return View();
            }

            try
            {
                var content = await HttpClient.GetStringAsync(targetUrl);
                ViewData["Response"] = content;
            }
            catch (Exception error)
            {
                ViewData["Error"] = error.Message;
            }
        }

        return View();
    }

    public IActionResult InsecureDeserialization(string? payload, bool hardened = false)
    {
        ViewData["Payload"] = payload;
        ViewData["Hardened"] = hardened;

        if (!string.IsNullOrWhiteSpace(payload))
        {
            try
            {
                using var document = JsonDocument.Parse(payload);
                var root = document.RootElement;
                var isAdmin = root.GetProperty("isAdmin").GetBoolean();
                var username = root.GetProperty("username").GetString() ?? "guest";
                ViewData["Result"] = hardened
                    ? "User data accepted. Admin elevation is ignored in hardened mode."
                    : $"Welcome {username}. Admin privileges granted: {isAdmin}.";
            }
            catch (Exception error)
            {
                ViewData["Error"] = error.Message;
            }
        }

        return View();
    }

    public IActionResult Xxe(string? xml, bool hardened = false)
    {
        ViewData["Xml"] = xml;
        ViewData["Hardened"] = hardened;

        if (!string.IsNullOrWhiteSpace(xml))
        {
            try
            {
                var settings = new XmlReaderSettings
                {
                    DtdProcessing = hardened ? DtdProcessing.Prohibit : DtdProcessing.Parse,
                    XmlResolver = hardened ? null : new XmlUrlResolver()
                };

                using var reader = XmlReader.Create(new StringReader(xml), settings);
                var document = new XmlDocument();
                document.Load(reader);
                ViewData["Result"] = document.DocumentElement?.InnerText ?? "Parsed successfully.";
            }
            catch (Exception error)
            {
                ViewData["Error"] = error.Message;
            }
        }

        return View();
    }

    public IActionResult TemplateInjection(string? template, bool hardened = false)
    {
        ViewData["Template"] = template;
        ViewData["Hardened"] = hardened;

        if (!string.IsNullOrWhiteSpace(template))
        {
            try
            {
                if (hardened)
                {
                    ViewData["Output"] = HtmlEncoder.Default.Encode(template ?? string.Empty);
                }
                else
                {
                    var scriptOptions = ScriptOptions.Default.WithImports("System", "System.IO", "System.Text");
                    var rendered = Regex.Replace(template ?? string.Empty, "\\{\\{(.*?)\\}\\}", match =>
                    {
                        var code = match.Groups[1].Value;
                        var result = CSharpScript.EvaluateAsync<object>(code, scriptOptions).GetAwaiter().GetResult();
                        return result?.ToString() ?? string.Empty;
                    });
                    ViewData["Output"] = rendered;
                }
            }
            catch (Exception error)
            {
                ViewData["Error"] = error.Message;
            }
        }

        return View();
    }

    public IActionResult LogicError(string? role = "user", bool hardened = false)
    {
        ViewData["Role"] = role;
        ViewData["Hardened"] = hardened;

        if (hardened)
        {
            ViewData["Result"] = "Only the actual application role is allowed to perform admin actions in hardened mode.";
        }
        else
        {
            ViewData["Result"] = role == "manager"
                ? "Action allowed: manager privileges granted based on supplied role."
                : "Action denied for non-manager role.";
        }

        return View();
    }

    public IActionResult RemoteCodeExecution(string? code, bool hardened = false)
    {
        ViewData["Code"] = code;
        ViewData["Hardened"] = hardened;

        if (!string.IsNullOrWhiteSpace(code))
        {
            try
            {
                if (hardened)
                {
                    if (!Regex.IsMatch(code, @"^[0-9+\-*/ ()]+$"))
                    {
                        ViewData["Error"] = "Only simple arithmetic expressions are allowed in hardened mode.";
                    }
                    else
                    {
                        var result = CSharpScript.EvaluateAsync<object>(code).GetAwaiter().GetResult();
                        ViewData["Result"] = result?.ToString() ?? "(no result)";
                    }
                }
                else
                {
                    var result = CSharpScript.EvaluateAsync<object>(code).GetAwaiter().GetResult();
                    ViewData["Result"] = $"Executed result: {result}";
                }
            }
            catch (Exception error)
            {
                ViewData["Error"] = error.Message;
            }
        }

        return View();
    }

    public IActionResult SameOriginPolicy(string? origin, bool hardened = false)
    {
        ViewData["Origin"] = origin ?? "https://malicious.example";
        ViewData["Hardened"] = hardened;

        if (!string.IsNullOrWhiteSpace(origin))
        {
            Response.Headers["Access-Control-Allow-Origin"] = hardened ? "https://trusted.student" : origin;
            Response.Headers["Access-Control-Allow-Credentials"] = hardened ? "true" : "true";
            ViewData["Result"] = hardened
                ? "CORS response is restricted to the trusted origin."
                : "CORS response allows the supplied origin, which weakens same-origin protections.";
        }

        return View();
    }

    public IActionResult Sso(string? returnUrl, bool hardened = false)
    {
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["Hardened"] = hardened;

        if (!string.IsNullOrWhiteSpace(returnUrl))
        {
            if (!hardened || Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            ViewData["Error"] = "SSO redirect blocked: only local return URLs are allowed in hardened mode.";
        }

        return View();
    }

    public IActionResult InformationDisclosure(bool trigger = false, bool hardened = false)
    {
        ViewData["Trigger"] = trigger;
        ViewData["Hardened"] = hardened;

        if (trigger)
        {
            try
            {
                throw new InvalidOperationException("Sensitive data path: /app/secrets/config.yaml");
            }
            catch (Exception ex)
            {
                ViewData["Result"] = hardened
                    ? "An error occurred. The application logged the details and displayed a generic message."
                    : ex.ToString();
            }
        }

        return View();
    }

    private static bool IsAllowedHost(string targetUrl)
    {
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var allowedHosts = new[] { "localhost", "127.0.0.1", "::1" };
        return (uri.Scheme == "http" || uri.Scheme == "https") && allowedHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase);
    }

    private static IEnumerable<Product> SearchProducts(string query, bool hardened)
    {
        using var connection = new SqliteConnection($"Data Source={DbFilePath}");
        connection.Open();

        using var command = connection.CreateCommand();
        if (hardened)
        {
            command.CommandText = "SELECT Id, Name, Description FROM Products WHERE Name LIKE @term OR Description LIKE @term";
            command.Parameters.AddWithValue("@term", $"%{query}%");
        }
        else
        {
            command.CommandText = $"SELECT Id, Name, Description FROM Products WHERE Name LIKE '%{query}%' OR Description LIKE '%{query}%'";
        }

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            yield return new Product(reader.GetInt32(0), reader.GetString(1), reader.GetString(2));
        }
    }

    private static void EnsureDatabase()
    {
        lock (DbInitLock)
        {
            if (DbInitialized)
            {
                return;
            }

            var folder = Path.GetDirectoryName(DbFilePath);
            if (!string.IsNullOrEmpty(folder))
            {
                Directory.CreateDirectory(folder);
            }

            using var connection = new SqliteConnection($"Data Source={DbFilePath}");
            connection.Open();

            using var createTable = connection.CreateCommand();
            createTable.CommandText = @"CREATE TABLE IF NOT EXISTS Products (
                Id INTEGER PRIMARY KEY,
                Name TEXT NOT NULL,
                Description TEXT NOT NULL
            );";
            createTable.ExecuteNonQuery();

            using var countCommand = connection.CreateCommand();
            countCommand.CommandText = "SELECT COUNT(*) FROM Products";
            var count = Convert.ToInt32(countCommand.ExecuteScalar());
            if (count == 0)
            {
                var insertCommand = connection.CreateCommand();
                insertCommand.CommandText = @"INSERT INTO Products (Name, Description) VALUES
                    ('Sports Bike', 'A lightweight bicycle for training'),
                    ('Tennis Racket', 'High-tension strings and comfortable grip'),
                    ('Camping Tent', 'Two-person tent with waterproof fly'),
                    ('Running Shoes', 'Cushioned shoes for long distance running');";
                insertCommand.ExecuteNonQuery();
            }

            DbInitialized = true;
        }
    }

    private static bool WithdrawVulnerable(BankAccount account, int amount)
    {
        if (account.Balance >= amount)
        {
            Thread.Sleep(25);
            account.Balance -= amount;
            return true;
        }

        return false;
    }

    private static bool WithdrawSafe(BankAccount account, int amount)
    {
        lock (BalanceLock)
        {
            if (account.Balance >= amount)
            {
                Thread.Sleep(25);
                account.Balance -= amount;
                return true;
            }
        }

        return false;
    }
}
