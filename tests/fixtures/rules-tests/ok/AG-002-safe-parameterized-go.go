// Copyright 2026 Minh Hoang Ton
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// AG-002 SAFE: parameterized queries with ? placeholders — should NOT fire
package catalog

import (
	"context"
	"database/sql"
)

type SafeProductRepository struct {
	db *sql.DB
}

// SearchProducts uses parameterized query — safe
func (r *SafeProductRepository) SearchProducts(name, category string, minPrice float64) ([]Product, error) {
	// Safe: ? placeholders, user data passed as separate args — not in SQL string
	rows, err := r.db.Query(
		"SELECT id, name, price FROM products WHERE name LIKE ? AND category = ? AND price >= ?",
		"%"+name+"%", category, minPrice,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProducts(rows)
}

// GetOrderByID uses parameterized query
func (r *SafeProductRepository) GetOrderByID(orderID int64) (*Order, error) {
	// Safe: $1 PostgreSQL style placeholder
	row := r.db.QueryRow("SELECT * FROM orders WHERE id = $1", orderID)
	return scanOrder(row)
}

// UpdateStock uses ExecContext with placeholder
func (r *SafeProductRepository) UpdateStock(ctx context.Context, productID int, quantity int) error {
	// Safe: separate parameter binding
	_, err := r.db.ExecContext(ctx,
		"UPDATE products SET stock = $1 WHERE id = $2",
		quantity, productID,
	)
	return err
}

// StaticQuery uses a fully static SQL string — also safe
func (r *SafeProductRepository) CountAll() (int, error) {
	var count int
	err := r.db.QueryRow("SELECT COUNT(*) FROM products WHERE active = TRUE").Scan(&count)
	return count, err
}
