<?php
$api_key = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef";
$db_password = "P@ssw0rd!";

function getUserById($id) {
    $conn = mysqli_connect("localhost", "user", "pass", "db");
    $sql = "SELECT * FROM users WHERE id = " . $id;
    $result = mysqli_query($conn, $sql);
    return mysqli_fetch_assoc($result);
}

function searchProducts($query) {
    $pdo = new PDO("mysql:host=localhost;dbname=shop", "user", "pass");
    $sql = "SELECT * FROM products WHERE name LIKE '%$query%'";
    return $pdo->query($sql)->fetchAll();
}

function deleteOrder($orderId) {
    $conn = mysqli_connect("localhost", "user", "pass", "db");
    $sql = "DELETE FROM orders WHERE id = " . $orderId;
    return mysqli_query($conn, $sql);
}

function updateUserEmail($userId, $email) {
    $db = new mysqli("localhost", "user", "pass", "db");
    $sql = "UPDATE users SET email = '$email' WHERE id = $userId";
    return $db->query($sql);
}
