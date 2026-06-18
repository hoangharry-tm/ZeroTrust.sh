package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

var ordersServiceURL = os.Getenv("ORDERS_SERVICE_URL")

func getOrder(w http.ResponseWriter, r *http.Request) {
	orderID := r.URL.Query().Get("orderId")
	userID := r.URL.Query().Get("userId")

	resp, err := http.Get(fmt.Sprintf("%s/orders/%s", ordersServiceURL, orderID))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var order map[string]interface{}
	json.Unmarshal(body, &order)

	order["requested_by"] = userID
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

func createOrder(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	resp, err := http.Post(
		fmt.Sprintf("%s/orders", ordersServiceURL),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func processPayment(w http.ResponseWriter, r *http.Request) {
	orderID := r.URL.Query().Get("orderId")
	body, _ := io.ReadAll(r.Body)
	resp, err := http.Post(
		fmt.Sprintf("%s/payments/process/%s", ordersServiceURL, orderID),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		http.Error(w, "payment error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"status":"ok"}`))
}

func main() {
	http.HandleFunc("/api/orders", getOrder)
	http.HandleFunc("/api/orders/create", createOrder)
	http.HandleFunc("/api/payments/process", processPayment)
	http.HandleFunc("/api/health", healthHandler)

	log.Printf("Gateway starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
