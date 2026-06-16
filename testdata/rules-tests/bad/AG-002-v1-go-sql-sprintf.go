// AG-002 V1: db.Query() with fmt.Sprintf() SQL string — Go SQL injection
// Realistic AI-generated product catalog service — SQL injection via Sprintf
package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
)

type ProductRepository struct {
	db *sql.DB
}

// SearchProducts returns products matching the search criteria.
// VULN: fmt.Sprintf used to build SQL query with user input
func (r *ProductRepository) SearchProducts(name, category string, minPrice float64) ([]Product, error) {
	// VULN V1: direct fmt.Sprintf in db.Query()
	rows, err := r.db.Query(
		fmt.Sprintf("SELECT id, name, price FROM products WHERE name LIKE '%%%s%%' AND category = '%s' AND price >= %f",
			name, category, minPrice),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProducts(rows)
}

// GetOrderByID retrieves a single order.
// VULN V1: fmt.Sprintf in db.QueryRow()
func (r *ProductRepository) GetOrderByID(orderID string) (*Order, error) {
	row := r.db.QueryRow(fmt.Sprintf("SELECT * FROM orders WHERE id = '%s'", orderID))
	return scanOrder(row)
}

// DeleteProduct removes a product by ID.
// VULN V1: fmt.Sprintf in db.Exec()
func (r *ProductRepository) DeleteProduct(productID string) error {
	_, err := r.db.Exec(fmt.Sprintf("DELETE FROM products WHERE id = '%s'", productID))
	return err
}

// UpdateStockWithContext uses context variant.
// VULN V7: db.ExecContext with fmt.Sprintf
func (r *ProductRepository) UpdateStockWithContext(ctx context.Context, productID string, quantity int) error {
	_, err := r.db.ExecContext(ctx,
		fmt.Sprintf("UPDATE products SET stock = %d WHERE id = '%s'", quantity, productID))
	return err
}

// BuildFilterQuery assembles query then executes.
// VULN V4: Sprintf result in variable then db.Query
func (r *ProductRepository) FilterByTag(tag string) ([]Product, error) {
	sql := fmt.Sprintf("SELECT * FROM products WHERE tag = '%s'", tag)
	rows, err := r.db.Query(sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProducts(rows)
}

// SearchByName uses string concatenation — V5
func (r *ProductRepository) SearchByName(name string) ([]Product, error) {
	// VULN V5: string concat in db.Query
	rows, err := r.db.Query("SELECT * FROM products WHERE name LIKE '%" + name + "%'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProducts(rows)
}

// HTTPHandler extracts from request and calls vulnerable function
func (r *ProductRepository) HandleSearch(w http.ResponseWriter, req *http.Request) {
	name := req.URL.Query().Get("name")
	rows, _ := r.db.Query(fmt.Sprintf("SELECT * FROM products WHERE name = '%s'", name))
	defer rows.Close()
}

type Product struct{ ID int; Name string; Price float64 }
type Order struct{ ID int }
func scanProducts(rows *sql.Rows) ([]Product, error) { return nil, nil }
func scanOrder(row *sql.Row) (*Order, error) { return nil, nil }
