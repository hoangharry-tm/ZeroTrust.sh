<?php
// Edge case: static SQL queries only, no user input interpolation
function getUserById(int $id): ?array {
    $stmt = $pdo->prepare("SELECT id, username, email FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

function searchProducts(string $query): array {
    $stmt = $pdo->prepare(
        "SELECT id, name, price FROM products WHERE name ILIKE ?"
    );
    $stmt->execute(["%$query%"]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function createOrder(int $userId, int $productId, int $qty): int {
    $stmt = $pdo->prepare(
        "INSERT INTO orders (user_id, product_id, quantity) VALUES (?, ?, ?)"
    );
    $stmt->execute([$userId, $productId, $qty]);
    return (int)$pdo->lastInsertId();
}
