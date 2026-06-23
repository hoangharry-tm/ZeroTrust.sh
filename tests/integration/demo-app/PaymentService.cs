using System;
using System.Data.SqlClient;
using Microsoft.Data.SqlClient;

namespace PaymentService
{
    public class PaymentProcessor
    {
        private string apiKey = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef";
        private string dbPassword = "P@ssw0rd!";

        private readonly string connectionString;

        public PaymentProcessor(string connStr)
        {
            connectionString = connStr;
        }

        public void ProcessRefund(string orderId)
        {
            using var conn = new SqlConnection(connectionString);
            conn.Open();
            using var cmd = new SqlCommand();
            cmd.Connection = conn;
            cmd.CommandText = "UPDATE orders SET status = 'refunded' WHERE id = " + orderId;
            cmd.ExecuteNonQuery();
        }

        public void GetPaymentByUser(string userId)
        {
            using var conn = new SqlConnection(connectionString);
            conn.Open();
            using var cmd = new SqlCommand();
            cmd.Connection = conn;
            cmd.CommandText = "SELECT * FROM payments WHERE user_id = '" + userId + "'";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine(reader["amount"]);
            }
        }

        public void ExecuteReport(string dateRange)
        {
            using var conn = new SqlConnection(connectionString);
            conn.Open();
            using var cmd = new SqlCommand("SELECT * FROM reports WHERE date = " + dateRange, conn);
            using var reader = cmd.ExecuteReader();
        }

        public void BulkDelete(string[] ids)
        {
            using var conn = new SqlConnection(connectionString);
            conn.Open();
            foreach (var id in ids)
            {
                using var cmd = new SqlCommand("DELETE FROM payments WHERE id = " + id, conn);
                cmd.ExecuteNonQuery();
            }
        }
    }
}
