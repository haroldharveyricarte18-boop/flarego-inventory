package main

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq" // Required PostgreSQL driver
)

// --- MODELS ---

type User struct {
	ID              int
	Username        string
	DisplayName     string
	ProfilePic      string
	Role            string
	ThemePreference string
	SecretAnswer    string
}

type Product struct {
	ID           int
	Name         string
	Price        string
	CostPrice    float64
	Desc         string
	Stock        string
	NumericStock int
}

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

	if _, err := os.Stat("uploads"); os.IsNotExist(err) {
		os.Mkdir("uploads", 0755)
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

	db.Exec("ALTER TABLE products ADD COLUMN IF NOT EXISTS cost_price NUMERIC(10,2) DEFAULT 0.00;")
	db.Exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'staff';")

	db.Exec(`INSERT INTO users (username, password, display_name, role) 
             VALUES ('admin', 'admin123', 'System Admin', 'admin') 
             ON CONFLICT (username) DO UPDATE SET role = 'admin'`)
}

// --- UTILITIES ---

func parsePrice(priceStr string) float64 {
	replacer := strings.NewReplacer("$", "", "₱", "", "PHP", "", ",", "", " ", "")
	cleanPrice := replacer.Replace(priceStr)
	price, _ := strconv.ParseFloat(cleanPrice, 64)
	return price
}

func logActivity(action, name, details string) {
	db.Exec("INSERT INTO activity_logs (action, product_name, details) VALUES ($1, $2, $3)", action, name, details)
}

func countSalesToday() int {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='Sale' AND created_at >= CURRENT_DATE").Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func sub(a, b int) int { return a - b }

// --- MIDDLEWARE ---

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

// --- HANDLERS ---

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
		http.SetCookie(w, &http.Cookie{Name: "session_token", Value: username, Path: "/", HttpOnly: true})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
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
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func userManagementHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, username, display_name, role, profile_pic FROM users ORDER BY id ASC")
	if err != nil {
		http.Error(w, "Database error", 500)
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
	tmpl.Execute(w, map[string]interface{}{"Users": users})
}

func changeRoleHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	newRole := r.URL.Query().Get("role")

	_, err := db.Exec("UPDATE users SET role=$1 WHERE id=$2 AND username != 'admin'", newRole, id)
	if err != nil {
		http.Error(w, "Update failed", 500)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_token")
	var u User
	db.QueryRow("SELECT id, username, display_name, profile_pic, role FROM users WHERE username=$1", cookie.Value).
		Scan(&u.ID, &u.Username, &u.DisplayName, &u.ProfilePic, &u.Role)

	var editItem *Product
	editID := r.URL.Query().Get("edit")
	if editID != "" {
		var p Product
		err := db.QueryRow("SELECT id, name, price, cost_price, description, stock FROM products WHERE id=$1", editID).
			Scan(&p.ID, &p.Name, &p.Price, &p.CostPrice, &p.Desc, &p.Stock)
		if err == nil {
			editItem = &p
		}
	}

	rows, _ := db.Query("SELECT id, name, price, cost_price, description, stock FROM products ORDER BY id DESC")
	defer rows.Close()

	var products []Product
	var totalValue, totalProfit float64
	var totalStockItems int
	var lowStockCount int

	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Name, &p.Price, &p.CostPrice, &p.Desc, &p.Stock)
		p.NumericStock = p.GetNumericStock()
		sellPrice := parsePrice(p.Price)
		totalValue += sellPrice * float64(p.NumericStock)
		totalProfit += (sellPrice - p.CostPrice) * float64(p.NumericStock)
		totalStockItems += p.NumericStock
		if p.NumericStock <= 5 {
			lowStockCount++
		}
		products = append(products, p)
	}

	healthScore := 100
	if len(products) > 0 {
		healthScore = 100 - (lowStockCount * 100 / len(products))
	}

	logRows, _ := db.Query("SELECT action, product_name, created_at FROM activity_logs ORDER BY created_at DESC LIMIT 5")
	defer logRows.Close()
	var logs []ActivityLog
	for logRows.Next() {
		var l ActivityLog
		logRows.Scan(&l.Action, &l.ProductName, &l.CreatedAt)
		logs = append(logs, l)
	}

	tmpl, _ := template.New("index.html").Funcs(template.FuncMap{"sub": sub}).ParseFiles("index.html")
	data := map[string]interface{}{
		"User":            u,
		"Products":        products,
		"Logs":            logs,
		"TotalValue":      fmt.Sprintf("%.2f", totalValue),
		"TotalProfit":     fmt.Sprintf("%.2f", totalProfit),
		"TotalStockItems": totalStockItems,
		"TotalSales":      countSalesToday(),
		"HealthScore":     healthScore,
		"EditItem":        editItem,
		"IsEditing":       editItem != nil,
	}
	tmpl.Execute(w, data)
}

func addHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		id := r.FormValue("id")
		name := r.FormValue("name")
		price := r.FormValue("price")
		cost, _ := strconv.ParseFloat(r.FormValue("cost_price"), 64)
		desc := r.FormValue("desc")
		stock := r.FormValue("stock")

		if id != "" {
			db.Exec("UPDATE products SET name=$1, price=$2, cost_price=$3, description=$4, stock=$5 WHERE id=$6", name, price, cost, desc, stock, id)
			logActivity("Updated", name, "Product info modified")
		} else {
			db.Exec("INSERT INTO products (name, price, cost_price, description, stock) VALUES ($1, $2, $3, $4, $5)", name, price, cost, desc, stock)
			logActivity("Added", name, "New product created")
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_token")
	r.ParseMultipartForm(5 << 20)
	displayName := r.FormValue("display_name")

	file, handler, err := r.FormFile("profile_pic_file")
	if err == nil {
		defer file.Close()
		path := "uploads/" + fmt.Sprintf("%d%s", time.Now().Unix(), filepath.Ext(handler.Filename))
		dst, _ := os.Create(path)
		defer dst.Close()
		io.Copy(dst, file)
		db.Exec("UPDATE users SET display_name=$1, profile_pic=$2 WHERE username=$3", displayName, "/"+path, cookie.Value)
	} else {
		db.Exec("UPDATE users SET display_name=$1 WHERE username=$2", displayName, cookie.Value)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func sellHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		id := r.FormValue("id")
		var name string
		db.QueryRow("SELECT name FROM products WHERE id=$1", id).Scan(&name)
		res, _ := db.Exec("UPDATE products SET stock = (stock::int - 1)::text WHERE id=$1 AND stock::int > 0", id)
		count, _ := res.RowsAffected()
		if count > 0 {
			logActivity("Sale", name, "Sold 1 unit")
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
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
	rows, _ := db.Query("SELECT name, price, stock FROM products")
	writer.Write([]string{"Name", "Price", "Stock"})
	for rows.Next() {
		var n, p, s string
		rows.Scan(&n, &p, &s)
		writer.Write([]string{n, p, s})
	}
	writer.Flush()
}

func main() {
	initDB()
	defer db.Close()

	http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/", checkAuth(homeHandler))

	// USER MANAGEMENT ROUTES
	http.HandleFunc("/users", checkAuth(adminOnly(userManagementHandler)))
	http.HandleFunc("/change-role", checkAuth(adminOnly(changeRoleHandler)))

	http.HandleFunc("/settings", checkAuth(func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("session_token")
		var u User
		db.QueryRow("SELECT display_name, profile_pic FROM users WHERE username=$1", cookie.Value).Scan(&u.DisplayName, &u.ProfilePic)
		tmpl, _ := template.ParseFiles("settings.html")
		tmpl.Execute(w, map[string]interface{}{"User": u})
	}))

	http.HandleFunc("/update-profile", checkAuth(updateProfileHandler))
	http.HandleFunc("/logout", checkAuth(logoutHandler))
	http.HandleFunc("/sell", checkAuth(sellHandler))

	http.HandleFunc("/add", checkAuth(adminOnly(addHandler)))
	http.HandleFunc("/delete", checkAuth(adminOnly(deleteHandler)))
	http.HandleFunc("/export", checkAuth(adminOnly(exportHandler)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Flarego ERP active on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
