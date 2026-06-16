import { Pool } from "pg";

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
});

export async function getUserById(id: number) {
  const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
  return result.rows[0];
}

export async function getOrdersByUser(userId: number) {
  const result = await pool.query(
    "SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC",
    [userId]
  );
  return result.rows;
}

export async function createUser(name: string, email: string) {
  const result = await pool.query(
    "INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id",
    [name, email]
  );
  return result.rows[0].id;
}

export async function updateEmail(userId: number, email: string) {
  await pool.query("UPDATE users SET email = $1 WHERE id = $2", [email, userId]);
}
