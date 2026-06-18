import { Pool } from "pg";
import dotenv from "dotenv";

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
});

export async function queryUser(userId: number) {
  const result = await pool.query(
    "SELECT id, username, role FROM users WHERE id = $1",
    [userId],
  );
  return result.rows[0] || null;
}

export async function searchProducts(searchQuery: string) {
  const result = await pool.query(
    "SELECT id, name, price FROM products WHERE name ILIKE $1",
    [`%${searchQuery}%`],
  );
  return result.rows;
}

export async function getOrdersByUser(userId: number) {
  const result = await pool.query(
    "SELECT id, product_id, quantity, status FROM orders WHERE user_id = $1",
    [userId],
  );
  return result.rows;
}
