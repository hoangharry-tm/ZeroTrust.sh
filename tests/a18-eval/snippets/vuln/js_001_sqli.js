async function getUser(db, userId) {
  const result = await db.query(`SELECT * FROM users WHERE id = '${userId}'`);
  return result.rows[0];
}
