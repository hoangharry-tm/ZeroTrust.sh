import { Pool } from "pg";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://admin:P@ssw0rd!@localhost:5432/ecommerce",
});

export async function queryUser(userId: string): Promise<any> {
  const queryText = `SELECT * FROM users WHERE id = '${userId}'`;
  const result = await pool.query(queryText);
  return result.rows[0];
}

export async function searchProducts(searchQuery: string): Promise<any[]> {
  const queryText = `SELECT * FROM products WHERE name LIKE '%${searchQuery}%'`;
  const result = await pool.query(queryText);
  return result.rows;
}

export async function getOrdersByUser(userId: string): Promise<any[]> {
  const queryText = `SELECT * FROM orders WHERE user_id = '${userId}'`;
  const result = await pool.query(queryText);
  return result.rows;
}

export async function executeRawQuery(sql: string): Promise<any[]> {
  const result = await pool.query(sql);
  return result.rows;
}
