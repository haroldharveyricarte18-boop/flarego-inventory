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
	Role            string // "admin" or "staff"
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
            profile_pic TEXT DEFAULT 'https://ui-avatars.com/api/?name=User&background=6366f1&color=fff',
            secret_answer TEXT,
            role TEXT DEFAULT 'staff',
            theme_preference TEXT DEFAULT 'light'
        );
    `)
	if err != nil {
		log.Fatal("Database init error:", err)
	}

	// Migrations
	db.Exec("ALTER TABLE products ADD COLUMN IF NOT EXISTS cost_price NUMERIC(10,2) DEFAULT 0.00;")
	db.Exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS secret_answer TEXT;")
	db.Exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'staff';")
	db.Exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_preference TEXT DEFAULT 'light';")

	// Seed default admin
	db.Exec(`INSERT INTO users (username, password, display_name, secret_answer, role) 
             VALUES ('admin', 'admin123', 'System Admin', 'flarego', 'admin') 
             ON CONFLICT (username) DO UPDATE SET role = 'admin'`)
}

// --- AUTH & ROLE MIDDLEWARE ---

func checkAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("session_token")
		var role string
		err := db.QueryRow("SELECT role FROM users WHERE username=$1", cookie.Value).Scan(&role)

		if err != nil || role != "admin" {
			http.Error(w, "Access Denied: Admin privileges required.", http.StatusForbidden)
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
			Value:    username,
			Path:     "/",
			HttpOnly: true,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
	}
}

// --- USER MANAGEMENT & PROFILE ---

func userManagementHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_token")
	var currentUser User
	db.QueryRow("SELECT id, username FROM users WHERE username=$1", cookie.Value).Scan(&currentUser.ID, &currentUser.Username)

	rows, err := db.Query("SELECT id, username, display_name, role, profile_pic FROM users ORDER BY id ASC")
	if err != nil {
		http.Error(w, "Database Error", 500)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.ProfilePic)
		users = append(users, u)
	}

	tmpl, _ := template.ParseFiles("users.html")
	data := map[string]interface{}{
		"Users":       users,
		"CurrentUser": currentUser,
	}
	tmpl.Execute(w, data)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_token")
	var u User
	err := db.QueryRow("SELECT id, username, display_name, profile_pic, theme_preference FROM users WHERE username=$1", cookie.Value).
		Scan(&u.ID, &u.Username, &u.DisplayName, &u.ProfilePic, &u.ThemePreference)
	if err != nil {
		http.Redirect(w, r, "/logout", http.StatusSeeOther)
		return
	}

	tmpl, _ := template.ParseFiles("profile.html")
	tmpl.Execute(w, map[string]interface{}{"User": u})
}

func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		cookie, _ := r.Cookie("session_token")
		displayName := r.FormValue("display_name")
		profilePic := r.FormValue("profile_pic")
		theme := r.FormValue("theme")

		_, err := db.Exec("UPDATE users SET display_name=$1, profile_pic=$2, theme_preference=$3 WHERE username=$4",
			displayName, profilePic, theme, cookie.Value)
		if err != nil {
			http.Error(w, "Update failed", 500)
			return
		}
	}
	// Redirect back to profile page with a success flag
	http.Redirect(w, r, "/profile?success=true", http.StatusSeeOther)
}

func changeRoleHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_token")
	var currentUserID int
	db.QueryRow("SELECT id FROM users WHERE username=$1", cookie.Value).Scan(&currentUserID)

	id := r.URL.Query().Get("id")
	newRole := r.URL.Query().Get("role")
	targetID, _ := strconv.Atoi(id)

	if targetID == currentUserID {
		http.Redirect(w, r, "/users?error=self_action", http.StatusSeeOther)
		return
	}

	_, err := db.Exec("UPDATE users SET role=$1 WHERE id=$2 AND username != 'admin'", newRole, targetID)
	if err != nil {
		http.Error(w, "Update failed", 500)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// --- REMAINING HANDLERS ---

func homeHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_token")
	var u User
	err := db.QueryRow("SELECT id, username, display_name, profile_pic, role, theme_preference FROM users WHERE username=$1", cookie.Value).
		Scan(&u.ID, &u.Username, &u.DisplayName, &u.ProfilePic, &u.Role, &u.ThemePreference)
	if err != nil {
		http.Redirect(w, r, "/logout", http.StatusSeeOther)
		return
	}

	rows, _ := db.Query("SELECT id, name, price, cost_price, description, stock FROM products ORDER BY id DESC")
	defer rows.Close()

	var products []Product
	var totalValue, totalProfit float64
	var totalStockItems int

	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Name, &p.Price, &p.CostPrice, &p.Desc, &p.Stock)
		p.NumericStock = p.GetNumericStock()

		sellPrice := parsePrice(p.Price)
		totalValue += sellPrice * float64(p.NumericStock)
		totalProfit += (sellPrice - p.CostPrice) * float64(p.NumericStock)
		totalStockItems += p.NumericStock
		products = append(products, p)
	}

	logRows, _ := db.Query("SELECT action, product_name, created_at FROM activity_logs ORDER BY created_at DESC LIMIT 5")
	defer logRows.Close()
	var logs []ActivityLog
	for logRows.Next() {
		var l ActivityLog
		logRows.Scan(&l.Action, &l.ProductName, &l.CreatedAt)
		logs = append(logs, l)
	}

	funcMap := template.FuncMap{"sub": sub}
	tmpl, _ := template.New("index.html").Funcs(funcMap).ParseFiles("index.html")

	data := map[string]interface{}{
		"User":            u,
		"Products":        products,
		"Logs":            logs,
		"TotalValue":      fmt.Sprintf("%.2f", totalValue),
		"TotalProfit":     fmt.Sprintf("%.2f", totalProfit),
		"TotalStockItems": totalStockItems,
		"HealthScore":     85,
	}
	tmpl.Execute(w, data)
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

	_, err := db.Exec("INSERT INTO users (username, password, display_name, secret_answer, role) VALUES ($1, $2, $3, $4, 'staff')",
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
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
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

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/reset", resetPasswordHandler)

	http.HandleFunc("/", checkAuth(homeHandler))
	http.HandleFunc("/profile", checkAuth(profileHandler))              // Added
	http.HandleFunc("/update-profile", checkAuth(updateProfileHandler)) // Updated
	http.HandleFunc("/logout", checkAuth(logoutHandler))
	http.HandleFunc("/sell", checkAuth(sellHandler))

	// Admin Only
	http.HandleFunc("/users", checkAuth(adminOnly(userManagementHandler)))
	http.HandleFunc("/change-role", checkAuth(adminOnly(changeRoleHandler)))
	http.HandleFunc("/add", checkAuth(adminOnly(addHandler)))
	http.HandleFunc("/delete", checkAuth(adminOnly(deleteHandler)))
	http.HandleFunc("/export", checkAuth(adminOnly(exportHandler)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Flarego ERP V3.0 active on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
