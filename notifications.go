package main

import (
	"encoding/json"
	"net/http"
	"time"
)

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
	err := db.QueryRow(
		"INSERT INTO notifications (title, message, created_at) VALUES ($1, $2, $3) RETURNING id, created_at",
		newNotif.Title, newNotif.Message, time.Now(),
	).Scan(&newNotif.ID, &newNotif.CreatedAt)

	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	hub.broadcast <- newNotif

	logActivity(r, "Broadcast", "Global Update", newNotif.Message)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Broadcast sent successfully",
		"data":    newNotif,
	})
}

func GetNotifications(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, title, message, created_at FROM notifications ORDER BY created_at DESC LIMIT 20")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var notifs []Notification = []Notification{}
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.Title, &n.Message, &n.CreatedAt); err == nil {
			notifs = append(notifs, n)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notifs)
}
