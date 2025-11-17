package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/scaleway/audit-sentinel/internal/config"
	"github.com/scaleway/audit-sentinel/internal/storage"
)

func main() {
	var (
		command = flag.String("command", "", "Migration command: up, down, create")
		name    = flag.String("name", "", "Migration name (for create)")
	)
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	migrator, err := storage.NewMigrator(cfg.Database.URL)
	if err != nil {
		log.Fatalf("Failed to create migrator: %v", err)
	}
	defer migrator.Close()

	switch *command {
	case "up":
		if err := migrator.Up(); err != nil {
			log.Fatalf("Migration up failed: %v", err)
		}
		fmt.Println("Migrations applied successfully")
	case "down":
		if err := migrator.Down(); err != nil {
			log.Fatalf("Migration down failed: %v", err)
		}
		fmt.Println("Migrations rolled back successfully")
	case "create":
		if *name == "" {
			log.Fatal("Migration name is required for create command")
		}
		if err := migrator.Create(*name); err != nil {
			log.Fatalf("Failed to create migration: %v", err)
		}
		fmt.Printf("Migration created: %s\n", *name)
	default:
		fmt.Fprintf(os.Stderr, "Usage: %s -command [up|down|create] [-name migration_name]\n", os.Args[0])
		os.Exit(1)
	}
}
