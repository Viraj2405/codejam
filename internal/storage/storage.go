package storage

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// Storage represents the database storage layer
type Storage struct {
	db *sql.DB
}

// NewStorage creates a new storage instance
func NewStorage(dbURL string) (*Storage, error) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Storage{db: db}, nil
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}

// DB returns the underlying database connection
func (s *Storage) DB() *sql.DB {
	return s.db
}
