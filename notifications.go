package main

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"
)

// Notification represents a broadcast message
type Notification struct {
	ID        int       `json:"id"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
	IsRead    bool      `json:"is_read"`
}

var (
	notifications []Notification
	notifMutex    sync.Mutex
	notifFile     = "notifications.json"
)

// LoadNotifications from the JSON file on startup
func LoadNotifications() {
	file, err := os.ReadFile(notifFile)
	if err == nil {
		json.Unmarshal(file, &notifications)
	}
}

// SaveNotifications to the JSON file
func SaveNotifications() {
	data, _ := json.MarshalIndent(notifications, "", "  ")
	os.WriteFile(notifFile, data, 0644)
}

// BroadcastHandler handles the "Post Update" button from the Admin Dashboard
func BroadcastHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newNotif Notification
	if err := json.NewDecoder(r.Body).Decode(&newNotif); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	notifMutex.Lock()
	newNotif.ID = len(notifications) + 1
	newNotif.CreatedAt = time.Now()
	newNotif.IsRead = false
	notifications = append([]Notification{newNotif}, notifications...) // Add to top
	SaveNotifications()
	notifMutex.Unlock()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Broadcast sent!"})
}

// GetNotifications returns the list for the Bell Icon
func GetNotifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notifications)
}
