package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Product struct {
	Name  string
	Price string
	Desc  string
	Stock string
}

// NumericStock converts the Stock string to an int for HTML logic checks
func (p Product) NumericStock() int {
	val, _ := strconv.Atoi(p.Stock)
	return val
}

var products []Product

func saveData() {
	data, err := json.MarshalIndent(products, "", "  ")
	if err != nil {
		log.Println("Error saving data:", err)
		return
	}
	os.WriteFile("products.json", data, 0644)
}

func loadData() {
	data, err := os.ReadFile("products.json")
	if err != nil {
		products = []Product{}
		return
	}
	json.Unmarshal(data, &products)
}

func parsePrice(priceStr string) float64 {
	replacer := strings.NewReplacer("$", "", ",", "", " ", "")
	cleanPrice := replacer.Replace(priceStr)
	price, _ := strconv.ParseFloat(cleanPrice, 64)
	return price
}

// FIXED MAIN FOR DEPLOYMENT
func main() {
	loadData()

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/add", addHandler)
	http.HandleFunc("/delete", deleteHandler)
	http.HandleFunc("/export", exportHandler)

	// Step 1 Fix: Get port from environment variable for public hosting
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Fallback to 8080 for local testing
	}

	log.Printf("Server starting on port %s", port)
	// Listen on all interfaces (":PORT") instead of "localhost:PORT"
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("index.html")
	if err != nil {
		http.Error(w, "HTML file not found", http.StatusInternalServerError)
		return
	}

	searchTerm := strings.ToLower(r.URL.Query().Get("search"))
	sortBy := r.URL.Query().Get("sort")
	editID := r.URL.Query().Get("edit")

	var displayProducts []Product
	displayProducts = append([]Product(nil), products...)

	if searchTerm != "" {
		filtered := []Product{}
		for _, p := range displayProducts {
			if strings.Contains(strings.ToLower(p.Name), searchTerm) {
				filtered = append(filtered, p)
			}
		}
		displayProducts = filtered
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
		price := parsePrice(p.Price)
		stock, _ := strconv.ParseFloat(p.Stock, 64)
		totalValue += (price * stock)
	}

	var editItem *Product
	editIdx := -1
	isEditing := false
	if editID != "" {
		idx, err := strconv.Atoi(editID)
		if err == nil && idx >= 0 && idx < len(products) {
			editItem = &products[idx]
			editIdx = idx
			isEditing = true
		}
	}

	data := map[string]interface{}{
		"Title":      "Flarego Inventory",
		"Products":   displayProducts,
		"Search":     searchTerm,
		"SortBy":     sortBy,
		"EditItem":   editItem,
		"EditIdx":    editIdx,
		"IsEditing":  isEditing,
		"TotalValue": fmt.Sprintf("%.2f", totalValue),
	}
	tmpl.Execute(w, data)
}

func exportHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=inventory_report.csv")
	writer := csv.NewWriter(w)
	defer writer.Flush()
	writer.Write([]string{"Name", "Price", "Stock", "Description"})
	for _, p := range products {
		writer.Write([]string{p.Name, p.Price, p.Stock, p.Desc})
	}
}

func addHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		idStr := r.FormValue("id")
		newProd := Product{
			Name:  r.FormValue("name"),
			Price: r.FormValue("price"),
			Desc:  r.FormValue("desc"),
			Stock: r.FormValue("stock"),
		}
		if idStr != "" {
			id, _ := strconv.Atoi(idStr)
			if id >= 0 && id < len(products) {
				products[id] = newProd
			}
		} else {
			products = append(products, newProd)
		}
		saveData()
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err == nil && id >= 0 && id < len(products) {
		products = append(products[:id], products[id+1:]...)
		saveData()
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
