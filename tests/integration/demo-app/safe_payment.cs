using System;
using System.Data;
using Microsoft.Data.SqlClient;

public class SafePaymentService
{
    private readonly string _connectionString;

    public SafePaymentService(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("DefaultConnection")
            ?? Environment.GetEnvironmentVariable("DB_CONNECTION")
            ?? throw new InvalidOperationException("Database connection not configured");
    }

    public async Task ProcessRefund(int paymentId, decimal amount)
    {
        using var conn = new SqlConnection(_connectionString);
        await conn.OpenAsync();
        using var tx = conn.BeginTransaction(IsolationLevel.ReadCommitted);

        try
        {
            var cmd = new SqlCommand(
                "UPDATE payments SET status = 'refunded' WHERE id = @PaymentId AND amount = @Amount",
                conn, tx
            );
            cmd.Parameters.AddWithValue("@PaymentId", paymentId);
            cmd.Parameters.AddWithValue("@Amount", amount);
            await cmd.ExecuteNonQueryAsync();
            await tx.CommitAsync();
        }
        catch
        {
            await tx.RollbackAsync();
            throw;
        }
    }

    public async Task<List<Payment>> GetPaymentsByUser(int userId)
    {
        using var conn = new SqlConnection(_connectionString);
        var cmd = new SqlCommand(
            "SELECT id, amount, status, created_at FROM payments WHERE user_id = @UserId ORDER BY created_at DESC",
            conn
        );
        cmd.Parameters.AddWithValue("@UserId", userId);
        await conn.OpenAsync();
        using var reader = await cmd.ExecuteReaderAsync();
        var payments = new List<Payment>();
        while (await reader.ReadAsync())
        {
            payments.Add(new Payment
            {
                Id = reader.GetInt32(0),
                Amount = reader.GetDecimal(1),
                Status = reader.GetString(2),
                CreatedAt = reader.GetDateTime(3)
            });
        }
        return payments;
    }
}
