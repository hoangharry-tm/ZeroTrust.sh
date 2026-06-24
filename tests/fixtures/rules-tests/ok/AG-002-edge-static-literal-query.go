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

// AG-002 EDGE/SAFE: db.Query() with only a static literal — excluded by rule's `not` clause
package catalog

import (
	"database/sql"
)

type MaintenanceRepository struct {
	db *sql.DB
}

// CountActiveProducts uses a literal SQL string — should not fire (excluded)
func (r *MaintenanceRepository) CountActiveProducts() (int, error) {
	// Safe: rule excludes `db.Query("$LITERAL", ...)` patterns
	rows, err := r.db.Query("SELECT COUNT(*) FROM products WHERE active = TRUE", )
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var count int
	if rows.Next() {
		rows.Scan(&count)
	}
	return count, nil
}

// ListPendingOrders — static query, no user input
func (r *MaintenanceRepository) ListPendingOrders() (*sql.Rows, error) {
	return r.db.Query("SELECT id, customer_id, total FROM orders WHERE status = 'PENDING' ORDER BY created_at ASC LIMIT 100")
}
