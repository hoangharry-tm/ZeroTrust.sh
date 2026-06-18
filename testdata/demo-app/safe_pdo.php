<?php
declare(strict_types=1);

class SafeDatabase
{
    private PDO $pdo;

    public function __construct()
    {
        $dsn = sprintf(
            'pgsql:host=%s;dbname=%s',
            getenv('DB_HOST') ?: 'localhost',
            getenv('DB_NAME') ?: 'app'
        );
        $this->pdo = new PDO($dsn, getenv('DB_USER'), getenv('DB_PASSWORD'), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }

    public function getUserById(int $id): ?array
    {
        $stmt = $this->pdo->prepare("SELECT id, username, email FROM users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch() ?: null;
    }

    public function searchProducts(string $query): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT id, name, price FROM products WHERE name ILIKE ?"
        );
        $stmt->execute(["%$query%"]);
        return $stmt->fetchAll();
    }

    public function createOrder(int $userId, int $productId, int $quantity): int
    {
        $stmt = $this->pdo->prepare(
            "INSERT INTO orders (user_id, product_id, quantity, status) VALUES (?, ?, ?, 'pending')"
        );
        $stmt->execute([$userId, $productId, $quantity]);
        return (int)$this->pdo->lastInsertId();
    }
}
