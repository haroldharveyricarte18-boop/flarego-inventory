package main

import (
	"database/sql"
	"time"
)

// Notification structure with JSON tags for frontend compatibility
type Notification struct {
	ID        int       `json:"id"`
	UserID    *int      `json:"user_id"` // Pointer handles NULL values from DB
	Type      string    `json:"type"`    // 'login', 'broadcast', 'stock'
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	IsRead    bool      `json:"is_read"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateNotification saves a new notification to the database
func CreateNotification(db *sql.DB, userID *int, nType, title, message string) error {
	// Using ? placeholders for SQLite
	query := `INSERT INTO notifications (user_id, type, title, message, is_read, created_at) 
              VALUES (?, ?, ?, ?, 0, CURRENT_TIMESTAMP)`
	_, err := db.Exec(query, userID, nType, title, message)
	return err
}

// GetUserNotifications fetches the latest 10 notifications for a user or global broadcasts
func GetUserNotifications(db *sql.DB, userID int) ([]Notification, error) {
	// Added 'type' to the SELECT to match the struct fields
	query := `SELECT id, user_id, type, title, message, is_read, created_at 
              FROM notifications 
              WHERE user_id = ? OR user_id IS NULL 
              ORDER BY created_at DESC LIMIT 10`

	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notifications []Notification
	for rows.Next() {
		var n Notification
		// Scan must match the order of columns in the SELECT statement
		err := rows.Scan(&n.ID, &n.UserID, &n.Type, &n.Title, &n.Message, &n.IsRead, &n.CreatedAt)
		if err != nil {
			return nil, err
		}
		notifications = append(notifications, n)
	}
	return notifications, nil
}
