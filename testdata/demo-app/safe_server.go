package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

var db *sql.DB

func init() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL not set")
	}
	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	row := db.QueryRow("SELECT id, name FROM users WHERE id = $1", userID)
	var id int
	var name string
	if err := row.Scan(&id, &name); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"id": id, "name": name})
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	rows, err := db.Query("SELECT id, name FROM products WHERE name ILIKE $1", "%"+q+"%")
	if err != nil {
		http.Error(w, "query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var results []map[string]interface{}
	for rows.Next() {
		var id int
		var name string
		rows.Scan(&id, &name)
		results = append(results, map[string]interface{}{"id": id, "name": name})
	}
	json.NewEncoder(w).Encode(results)
}

func main() {
	http.HandleFunc("/user", userHandler)
	http.HandleFunc("/search", searchHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
