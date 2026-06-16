$userId = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);
$db->prepare("UPDATE accounts SET balance = ? WHERE user = ?");
mysqli_query($conn, "SELECT 1");
