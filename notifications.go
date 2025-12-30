package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// NOTE: The Notification struct is already defined in main.go.
// Go handles files in the same 'package main' as one big program,
// so we don't need to redefine it here.

// BroadcastHandler handles the broadcast request from the Admin Dashboard
func BroadcastHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Decode the notification from the request body
	var newNotif Notification
	if err := json.NewDecoder(r.Body).Decode(&newNotif); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// 2. Save to Database
	// We use the global 'db' variable from main.go
	err := db.QueryRow(
		"INSERT INTO notifications (title, message, created_at) VALUES ($1, $2, $3) RETURNING id, created_at",
		newNotif.Title, newNotif.Message, time.Now(),
	).Scan(&newNotif.ID, &newNotif.CreatedAt)

	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Push to Real-Time Hub
	// This sends the notification to all users currently connected via WebSocket
	hub.broadcast <- newNotif

	// 4. Log the activity for the audit trail
	logActivity(r, "Broadcast", "Global Update", newNotif.Message)

	// 5. Respond to the frontend
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Broadcast sent successfully",
		"data":    newNotif,
	})
}

// GetNotifications returns the latest 20 notifications for the UI Bell Icon
func GetNotifications(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, title, message, created_at FROM notifications ORDER BY created_at DESC LIMIT 20")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var notifs []Notification = []Notification{} // Initialize empty slice (prevents 'null' in JSON)
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.Title, &n.Message, &n.CreatedAt); err == nil {
			notifs = append(notifs, n)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notifs)
}
