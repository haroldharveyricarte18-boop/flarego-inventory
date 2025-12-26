package main

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	_ "github.com/lib/pq" // Required PostgreSQL driver
)

type Product struct {
	ID    int
	Name  string
	Price string
	Desc  string
	Stock string
}

func (p Product) NumericStock() int {
	val, _ := strconv.Atoi(p.Stock)
	return val
}

var db *sql.DB

// --- DATABASE LOGIC ---

func initDB() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Create table if it doesn't exist
	query := `
    CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name TEXT,
        price TEXT,
        description TEXT,
        stock TEXT
    );`
	_, err = db.Exec(query)
	if err != nil {
		log.Fatal("Could not create table:", err)
	}
}

// --- AUTHENTICATION MIDDLEWARE ---

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		adminUser := os.Getenv("ADMIN_USER")
		adminPass := os.Getenv("ADMIN_PASS")

		if !ok || user != adminUser || pass != adminPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// --- HELPERS ---

func parsePrice(priceStr string) float64 {
	replacer := strings.NewReplacer("$", "", ",", "", " ", "")
	cleanPrice := replacer.Replace(priceStr)
	price, _ := strconv.ParseFloat(cleanPrice, 64)
	return price
}

// --- MAIN ---

func main() {
	initDB()
	defer db.Close()

	// All routes are now protected by basicAuth
	http.HandleFunc("/", basicAuth(homeHandler))
	http.HandleFunc("/add", basicAuth(addHandler))
	http.HandleFunc("/delete", basicAuth(deleteHandler))
	http.HandleFunc("/export", basicAuth(exportHandler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server secure on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// --- HANDLERS ---

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("index.html")
	if err != nil {
		http.Error(w, "HTML file not found", 500)
		return
	}

	// Load from DB
	rows, err := db.Query("SELECT id, name, price, description, stock FROM products")
	if err != nil {
		http.Error(w, "DB Error", 500)
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Name, &p.Price, &p.Desc, &p.Stock)
		products = append(products, p)
	}

	// Search and Sort Logic
	searchTerm := strings.ToLower(r.URL.Query().Get("search"))
	sortBy := r.URL.Query().Get("sort")
	editID := r.URL.Query().Get("edit")

	var displayProducts []Product
	var lowStockCount int // NEW: Counter for low stock alerts

	for _, p := range products {
		// Calculate Low Stock (<= 5 units)
		if p.NumericStock() <= 5 {
			lowStockCount++
		}

		// Filter for display
		if searchTerm == "" || strings.Contains(strings.ToLower(p.Name), searchTerm) {
			displayProducts = append(displayProducts, p)
		}
	}

	if sortBy == "name" {
		sort.Slice(displayProducts, func(i, j int) bool {
			return strings.ToLower(displayProducts[i].Name) < strings.ToLower(displayProducts[j].Name)
		})
	} else if sortBy == "price" {
		sort.Slice(displayProducts, func(i, j int) bool {
			return parsePrice(displayProducts[i].Price) < parsePrice(displayProducts[j].Price)
		})
	}

	var totalValue float64
	for _, p := range products {
		totalValue += (parsePrice(p.Price) * float64(p.NumericStock()))
	}

	var editItem *Product
	var editIdx int = -1
	if editID != "" {
		id, _ := strconv.Atoi(editID)
		for i, p := range products {
			if p.ID == id {
				editItem = &products[i]
				editIdx = id
				break
			}
		}
	}

	data := map[string]interface{}{
		"Title":         "Flarego Secure Inventory",
		"Products":      displayProducts,
		"TotalValue":    fmt.Sprintf("%.2f", totalValue),
		"LowStockCount": lowStockCount, // NEW: Pass to Professional UI
		"Search":        searchTerm,    // NEW: Keep search bar filled
		"EditItem":      editItem,
		"EditIdx":       editIdx,
		"IsEditing":     editItem != nil,
	}
	tmpl.Execute(w, data)
}

func addHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		idStr := r.FormValue("id")
		name := r.FormValue("name")
		price := r.FormValue("price")
		desc := r.FormValue("desc")
		stock := r.FormValue("stock")

		if idStr != "" && idStr != "-1" {
			// Update
			db.Exec("UPDATE products SET name=$1, price=$2, description=$3, stock=$4 WHERE id=$5",
				name, price, desc, stock, idStr)
		} else {
			// Insert
			db.Exec("INSERT INTO products (name, price, description, stock) VALUES ($1, $2, $3, $4)",
				name, price, desc, stock)
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db.Exec("DELETE FROM products WHERE id=$1", id)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func exportHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=inventory.csv")
	writer := csv.NewWriter(w)
	defer writer.Flush()

	rows, _ := db.Query("SELECT name, price, stock, description FROM products")
	writer.Write([]string{"Name", "Price", "Stock", "Description"})
	for rows.Next() {
		var name, price, stock, desc string
		rows.Scan(&name, &price, &stock, &desc)
		writer.Write([]string{name, price, stock, desc})
	}
}
