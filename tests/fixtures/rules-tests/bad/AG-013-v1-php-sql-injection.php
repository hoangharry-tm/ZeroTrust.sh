$userId = $_GET['id'];
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $userId);
$db->query("UPDATE accounts SET balance = 0 WHERE user = " . $user);
$pdo->query("DELETE FROM sessions WHERE id = $sessionId");
