// Edge case: dynamic table name from allowlist only
const ALLOWED_TABLES = ["users", "products", "orders"];

async function queryTable(table: string, id: number) {
  if (!ALLOWED_TABLES.includes(table)) {
    throw new Error("Invalid table");
  }
  const result = await pool.query(
    `SELECT * FROM ${table} WHERE id = $1`,
    [id]
  );
  return result.rows;
}

// Column names from schema enum, not user input
const column = schema.columns[req.params.column];
if (column) {
  const result = await pool.query(
    `SELECT ${column} FROM products WHERE id = $1`,
    [productId]
  );
}
