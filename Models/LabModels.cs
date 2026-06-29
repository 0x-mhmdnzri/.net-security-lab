namespace SecurityLab.Models;

public sealed record Product(int Id, string Name, string Description);

public sealed record Document(int Id, string Title, string Owner);

public sealed record BankAccount
{
    public int Balance { get; set; }
}

public sealed record RaceResult(string Attempt, bool Success);
