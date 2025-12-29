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

// User struct for profile settings
type User struct {
	ID              int
	Username        string
	DisplayName     string
	ProfilePic      string
	ThemePreference string
	SecretAnswer    string
}

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
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username TEXT UNIQUE,
			password TEXT,
			display_name TEXT,
			profile_pic TEXT DEFAULT 'https://ui-avatars.com/api/?name=Admin&background=6366f1&color=fff',
			secret_answer TEXT,
			theme_preference TEXT DEFAULT 'light'
		);
	`)
	if err != nil {
		log.Fatal("Database init error:", err)
	}

	// Migrations: Add columns if they don't exist
	db.Exec("ALTER TABLE products ADD COLUMN IF NOT EXISTS cost_price NUMERIC(10,2) DEFAULT 0.00;")
	db.Exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS secret_answer TEXT;")

	// Seed default user (Username: admin | Password: admin123)
	db.Exec(`INSERT INTO users (username, password, display_name, secret_answer) 
			 VALUES ('admin', 'admin123', 'System Admin', 'flarego') 
			 ON CONFLICT (username) DO NOTHING`)
}

// --- AUTH MIDDLEWARE ---

func checkAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil || cookie.Value != "flarego_authenticated" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// --- AUTH HANDLERS ---

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, _ := template.ParseFiles("login.html")
		tmpl.Execute(w, nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var dbPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username=$1", username).Scan(&dbPassword)

	if err == nil && password == dbPassword {
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "flarego_authenticated",
			Path:     "/",
			HttpOnly: true,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, _ := template.ParseFiles("register.html")
		tmpl.Execute(w, nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	displayName := r.FormValue("display_name")
	secret := strings.ToLower(strings.TrimSpace(r.FormValue("secret")))

	_, err := db.Exec("INSERT INTO users (username, password, display_name, secret_answer) VALUES ($1, $2, $3, $4)",
		username, password, displayName, secret)

	if err != nil {
		http.Redirect(w, r, "/register?error=exists", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login?registered=true", http.StatusSeeOther)
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, _ := template.ParseFiles("reset.html")
		tmpl.Execute(w, nil)
		return
	}

	username := r.FormValue("username")
	secret := strings.ToLower(strings.TrimSpace(r.FormValue("secret")))
	newPassword := r.FormValue("new_password")

	var dbSecret string
	err := db.QueryRow("SELECT secret_answer FROM users WHERE username=$1", username).Scan(&dbSecret)

	if err == nil && secret == dbSecret {
		db.Exec("UPDATE users SET password=$1 WHERE username=$2", newPassword, username)
		http.Redirect(w, r, "/login?reset=success", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/reset?error=invalid", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- MAIN HANDLERS ---

func homeHandler(w http.ResponseWriter, r *http.Request) {
	funcMap := template.FuncMap{"sub": sub}
	tmpl, err := template.New("index.html").Funcs(funcMap).ParseFiles("index.html")
	if err != nil {
		http.Error(w, "Template Error: "+err.Error(), 500)
		return
	}

	var u User
	err = db.QueryRow("SELECT id, username, display_name, profile_pic FROM users LIMIT 1").
		Scan(&u.ID, &u.Username, &u.DisplayName, &u.ProfilePic)
	if err != nil {
		u.DisplayName = "Admin"
	}

	rows, err := db.Query("SELECT id, name, price, cost_price, description, stock FROM products ORDER BY id DESC")
	if err != nil {
		http.Error(w, "Database Query Error", 500)
		return
	}
	defer rows.Close()

	var products []Product
	var totalValue, totalProfit float64
	var totalStockItems, lowStockCount int

	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Name, &p.Price, &p.CostPrice, &p.Desc, &p.Stock)
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

	data := map[string]interface{}{
		"User":            u,
		"Products":        products,
		"TotalValue":      fmt.Sprintf("%.2f", totalValue),
		"TotalProfit":     fmt.Sprintf("%.2f", totalProfit),
		"TotalStockItems": totalStockItems,
		"HealthScore":     100,
	}
	tmpl.Execute(w, data)
}

func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		displayName := r.FormValue("display_name")
		profilePic := r.FormValue("profile_pic")
		db.Exec("UPDATE users SET display_name=$1, profile_pic=$2 WHERE id=(SELECT id FROM users LIMIT 1)", displayName, profilePic)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func addHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		name := r.FormValue("name")
		price := r.FormValue("price")
		cost, _ := strconv.ParseFloat(r.FormValue("cost_price"), 64)
		desc := r.FormValue("desc")
		stock := r.FormValue("stock")
		db.Exec("INSERT INTO products (name, price, cost_price, description, stock) VALUES ($1, $2, $3, $4, $5)", name, price, cost, desc, stock)
		logActivity("Added", name, "New product created")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func sellHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		id := r.FormValue("id")
		db.Exec("UPDATE products SET stock = (stock::int - 1)::text WHERE id=$1 AND stock::int > 0", id)
		logActivity("Sale", "ID:"+id, "Sold 1 unit")
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

// --- HELPERS ---

func parsePrice(priceStr string) float64 {
	replacer := strings.NewReplacer("$", "", "₱", "", "PHP", "", ",", "", " ", "")
	cleanPrice := replacer.Replace(priceStr)
	price, _ := strconv.ParseFloat(cleanPrice, 64)
	return price
}

func logActivity(action, name, details string) {
	db.Exec("INSERT INTO activity_logs (action, product_name, details) VALUES ($1, $2, $3)", action, name, details)
}

func sub(a, b int) int { return a - b }

func main() {
	initDB()
	defer db.Close()

	// Public Routes
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/reset", resetPasswordHandler)

	// Protected Routes (require login)
	http.HandleFunc("/", checkAuth(homeHandler))
	http.HandleFunc("/logout", checkAuth(logoutHandler))
	http.HandleFunc("/add", checkAuth(addHandler))
	http.HandleFunc("/sell", checkAuth(sellHandler))
	http.HandleFunc("/delete", checkAuth(deleteHandler))
	http.HandleFunc("/export", checkAuth(exportHandler))
	http.HandleFunc("/update-profile", checkAuth(updateProfileHandler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Flarego ERP V2.9 active on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
