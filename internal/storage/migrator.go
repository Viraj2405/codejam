package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/lib/pq"
)

// Migrator handles database migrations
type Migrator struct {
	dbURL string
	db    *sql.DB
}

// NewMigrator creates a new migrator instance
func NewMigrator(dbURL string) (*Migrator, error) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Migrator{
		dbURL: dbURL,
		db:    db,
	}, nil
}

// Close closes the database connection
func (m *Migrator) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// Up runs all pending migrations
func (m *Migrator) Up() error {
	// Create migrations table if it doesn't exist
	if err := m.createMigrationsTable(); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get all migration files
	migrationsDir := "migrations"
	files, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Filter and sort migration files
	var upFiles []string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".up.sql") {
			upFiles = append(upFiles, filepath.Join(migrationsDir, file.Name()))
		}
	}
	sort.Strings(upFiles)

	// Execute each migration
	for _, file := range upFiles {
		migrationName := filepath.Base(file)

		// Check if already applied
		applied, err := m.isMigrationApplied(migrationName)
		if err != nil {
			return fmt.Errorf("failed to check migration status: %w", err)
		}
		if applied {
			fmt.Printf("Migration %s already applied, skipping\n", migrationName)
			continue
		}

		// Read migration file
		sql, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", file, err)
		}

		// Execute migration
		fmt.Printf("Applying migration: %s\n", migrationName)
		if _, err := m.db.Exec(string(sql)); err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", migrationName, err)
		}

		// Record migration
		if err := m.recordMigration(migrationName); err != nil {
			return fmt.Errorf("failed to record migration: %w", err)
		}

		fmt.Printf("Migration %s applied successfully\n", migrationName)
	}

	return nil
}

// Down rolls back the last migration
func (m *Migrator) Down() error {
	// Get the last applied migration
	var lastMigration string
	err := m.db.QueryRow(`
		SELECT name FROM schema_migrations 
		ORDER BY applied_at DESC 
		LIMIT 1
	`).Scan(&lastMigration)
	if err == sql.ErrNoRows {
		return fmt.Errorf("no migrations to rollback")
	}
	if err != nil {
		return fmt.Errorf("failed to get last migration: %w", err)
	}

	// Find corresponding down file
	migrationsDir := "migrations"
	downFile := filepath.Join(migrationsDir, strings.Replace(lastMigration, ".up.sql", ".down.sql", 1))

	// Check if down file exists
	if _, err := os.Stat(downFile); os.IsNotExist(err) {
		return fmt.Errorf("down migration file not found: %s", downFile)
	}

	// Read and execute down migration
	sql, err := os.ReadFile(downFile)
	if err != nil {
		return fmt.Errorf("failed to read down migration: %w", err)
	}

	fmt.Printf("Rolling back migration: %s\n", lastMigration)
	if _, err := m.db.Exec(string(sql)); err != nil {
		return fmt.Errorf("failed to execute down migration: %w", err)
	}

	// Remove migration record
	if _, err := m.db.Exec("DELETE FROM schema_migrations WHERE name = $1", lastMigration); err != nil {
		return fmt.Errorf("failed to remove migration record: %w", err)
	}

	fmt.Printf("Migration %s rolled back successfully\n", lastMigration)
	return nil
}

// Create creates a new migration file
func (m *Migrator) Create(name string) error {
	migrationsDir := "migrations"

	// Get next migration number
	nextNum := m.getNextMigrationNumber()

	// Create migration files
	upFile := filepath.Join(migrationsDir, fmt.Sprintf("%s_%s.up.sql", nextNum, name))
	downFile := filepath.Join(migrationsDir, fmt.Sprintf("%s_%s.down.sql", nextNum, name))

	if err := os.WriteFile(upFile, []byte("-- Migration up\n"), 0644); err != nil {
		return err
	}

	if err := os.WriteFile(downFile, []byte("-- Migration down\n"), 0644); err != nil {
		return err
	}

	fmt.Printf("Created migration files: %s, %s\n", upFile, downFile)
	return nil
}

// createMigrationsTable creates the schema_migrations table
func (m *Migrator) createMigrationsTable() error {
	_, err := m.db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`)
	return err
}

// isMigrationApplied checks if a migration has been applied
func (m *Migrator) isMigrationApplied(name string) (bool, error) {
	var count int
	err := m.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE name = $1", name).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// recordMigration records that a migration has been applied
func (m *Migrator) recordMigration(name string) error {
	_, err := m.db.Exec("INSERT INTO schema_migrations (name) VALUES ($1)", name)
	return err
}

// getNextMigrationNumber gets the next migration number
func (m *Migrator) getNextMigrationNumber() string {
	migrationsDir := "migrations"
	files, err := os.ReadDir(migrationsDir)
	if err != nil {
		return "002"
	}

	maxNum := 0
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".up.sql") {
			var num int
			parts := strings.Split(file.Name(), "_")
			if len(parts) > 0 {
				fmt.Sscanf(parts[0], "%d", &num)
				if num > maxNum {
					maxNum = num
				}
			}
		}
	}

	return fmt.Sprintf("%03d", maxNum+1)
}
