package main

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq" // Required PostgreSQL driver
)

// Product includes CostPrice for profit calculations
type Product struct {
	ID           int
	Name         string
	Price        string  // Selling Price (Display)
	CostPrice    float64 // Buying Price (Calculation)
	Desc         string
	Stock        string
	NumericStock int
}

// ActivityLog for the audit trail
type ActivityLog struct {
	ID          int
	Action      string
	ProductName string
	Details     string
	CreatedAt   time.Time
}

func (p Product) GetNumericStock() int {
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

	// Ensure core tables and columns exist
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name TEXT,
            price TEXT,
            description TEXT,
            stock TEXT,
            cost_price NUMERIC(10,2) DEFAULT 0.00
        );
        CREATE TABLE IF NOT EXISTS activity_logs (
            id SERIAL PRIMARY KEY,
            action TEXT,
            product_name TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `)
	if err != nil {
		log.Fatal("Database init error:", err)
	}

	// Migration check
	db.Exec("ALTER TABLE products ADD COLUMN IF NOT EXISTS cost_price NUMERIC(10,2) DEFAULT 0.00;")
}

// --- HELPERS ---

func parsePrice(priceStr string) float64 {
	replacer := strings.NewReplacer("$", "", "₱", "", "PHP", "", ",", "", " ", "")
	cleanPrice := replacer.Replace(priceStr)
	price, _ := strconv.ParseFloat(cleanPrice, 64)
	return price
}

func logActivity(action, name, details string) {
	_, err := db.Exec("INSERT INTO activity_logs (action, product_name, details) VALUES ($1, $2, $3)",
		action, name, details)
	if err != nil {
		log.Printf("Logging error: %v", err)
	}
}

func sub(a, b int) int { return a - b }

// --- HANDLERS ---

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Add parsePrice to funcMap so HTML can use it for calculations
	funcMap := template.FuncMap{
		"sub":        sub,
		"parsePrice": parsePrice,
	}

	tmpl, err := template.New("index.html").Funcs(funcMap).ParseFiles("index.html")
	if err != nil {
		http.Error(w, "Template Error: "+err.Error(), 500)
		return
	}

	rows, err := db.Query("SELECT id, name, price, cost_price, description, stock FROM products ORDER BY id DESC")
	if err != nil {
		http.Error(w, "Database Query Error", 500)
		return
	}
	defer rows.Close()

	var products []Product
	var totalValue float64
	var totalProfit float64
	var totalStockItems int
	var lowStockCount int

	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Price, &p.CostPrice, &p.Desc, &p.Stock); err != nil {
			continue
		}
		p.NumericStock = p.GetNumericStock()

		if p.NumericStock <= 5 {
			lowStockCount++
		}

		sellPrice := parsePrice(p.Price)
		totalValue += sellPrice * float64(p.NumericStock)
		totalProfit += (sellPrice - p.CostPrice) * float64(p.NumericStock)
		totalStockItems += p.NumericStock

		products = append(products, p)
	}

	// New: Calculate Total Sales (sum of all 'Sale' actions in logs)
	var totalSalesCount int
	db.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='Sale'").Scan(&totalSalesCount)

	// Activity Logs
	logRows, _ := db.Query("SELECT action, product_name, created_at FROM activity_logs ORDER BY created_at DESC LIMIT 8")
	var logs []ActivityLog
	if logRows != nil {
		defer logRows.Close()
		for logRows.Next() {
			var l ActivityLog
			logRows.Scan(&l.Action, &l.ProductName, &l.CreatedAt)
			logs = append(logs, l)
		}
	}

	// Search logic
	searchTerm := strings.ToLower(r.URL.Query().Get("search"))
	var displayProducts []Product
	for _, p := range products {
		if searchTerm == "" || strings.Contains(strings.ToLower(p.Name), searchTerm) {
			displayProducts = append(displayProducts, p)
		}
	}

	// Health Calculation
	healthScore := 100
	if len(products) > 0 {
		healthScore = ((len(products) - lowStockCount) * 100) / len(products)
	}

	// Edit logic
	editID := r.URL.Query().Get("edit")
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
		"Products":        displayProducts,
		"Logs":            logs,
		"TotalValue":      fmt.Sprintf("%.2f", totalValue),
		"TotalProfit":     fmt.Sprintf("%.2f", totalProfit),
		"TotalStockItems": totalStockItems,
		"TotalSales":      totalSalesCount,
		"HealthScore":     healthScore,
		"Search":          searchTerm,
		"EditItem":        editItem,
		"EditIdx":         editIdx,
		"IsEditing":       editItem != nil,
	}
	tmpl.Execute(w, data)
}

func sellHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		id := r.FormValue("id")
		var name string
		var stockStr string

		err := db.QueryRow("SELECT name, stock FROM products WHERE id=$1", id).Scan(&name, &stockStr)
		stock, _ := strconv.Atoi(stockStr)

		if err == nil && stock > 0 {
			newStock := strconv.Itoa(stock - 1)
			db.Exec("UPDATE products SET stock=$1 WHERE id=$2", newStock, id)
			logActivity("Sale", name, "Sold 1 unit")
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func addHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		idStr := r.FormValue("id")
		name := r.FormValue("name")
		price := r.FormValue("price")
		cost, _ := strconv.ParseFloat(r.FormValue("cost_price"), 64)
		desc := r.FormValue("desc")
		stock := r.FormValue("stock")

		if idStr != "" && idStr != "-1" {
			db.Exec("UPDATE products SET name=$1, price=$2, cost_price=$3, description=$4, stock=$5 WHERE id=$6",
				name, price, cost, desc, stock, idStr)
			logActivity("Updated", name, "Modified entry")
		} else {
			db.Exec("INSERT INTO products (name, price, cost_price, description, stock) VALUES ($1, $2, $3, $4, $5)",
				name, price, cost, desc, stock)
			logActivity("Added", name, "New product created")
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var name string
	db.QueryRow("SELECT name FROM products WHERE id=$1", id).Scan(&name)
	db.Exec("DELETE FROM products WHERE id=$1", id)
	logActivity("Deleted", name, "Removed item")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func exportHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=flarego_inventory.csv")
	writer := csv.NewWriter(w)
	defer writer.Flush()

	rows, _ := db.Query("SELECT name, price, cost_price, stock FROM products")
	writer.Write([]string{"Name", "Sell Price", "Cost Price", "Stock"})
	for rows.Next() {
		var n, p, c, s string
		rows.Scan(&n, &p, &c, &s)
		writer.Write([]string{n, p, c, s})
	}
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != os.Getenv("ADMIN_USER") || pass != os.Getenv("ADMIN_PASS") {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", 401)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func main() {
	initDB()
	defer db.Close()
	http.HandleFunc("/", basicAuth(homeHandler))
	http.HandleFunc("/add", basicAuth(addHandler))
	http.HandleFunc("/sell", basicAuth(sellHandler)) // New route
	http.HandleFunc("/delete", basicAuth(deleteHandler))
	http.HandleFunc("/export", basicAuth(exportHandler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Flarego ERP V2.5 active on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
