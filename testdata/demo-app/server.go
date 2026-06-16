package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
)

func userHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID)
	db, _ := sql.Open("postgres", "user=app dbname=db")
	rows, err := db.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var name string
		rows.Scan(&id, &name)
		fmt.Fprintf(w, "%d: %s", id, name)
	}
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", q)
	db, _ := sql.Open("postgres", "user=app dbname=db")
	rows, _ := db.Query(query)
	defer rows.Close()
	for rows.Next() {
		var id int
		var name string
		rows.Scan(&id, &name)
		fmt.Fprintf(w, "%d: %s", id, name)
	}
}

func main() {
	http.HandleFunc("/user", userHandler)
	http.HandleFunc("/search", searchHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
