package main

import (
	"context"
	"log"

	"github.com/scaleway/audit-sentinel/internal/config"
	"github.com/scaleway/audit-sentinel/internal/ingestion"
	"github.com/scaleway/audit-sentinel/internal/storage"
	"github.com/scaleway/audit-sentinel/pkg/scaleway"
)

func main() {
	// Load config
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize storage
	store, err := storage.NewStorage(cfg.Database.URL)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// Create repositories
	eventRepo := storage.NewEventRepository(store.DB())

	// Create Scaleway client (mock or real depending on env)
	client := scaleway.NewClient(
		cfg.Scaleway.APIKey,
		cfg.Scaleway.ProjectID,
		cfg.Scaleway.OrganizationID,
		cfg.Scaleway.APIURL,
	)

	// Create ingestor
	ingestor := ingestion.NewIngestor(cfg, client, eventRepo)

	// Run ingestion
	ctx := context.Background()
	log.Println("Starting ingestion test...")

	if err := ingestor.Ingest(ctx); err != nil {
		log.Fatalf("Ingestion failed: %v", err)
	}

	log.Println("Ingestion completed successfully!")
	log.Println("Check the database to see stored events:")
	log.Println(`  psql -U auditsentinel -d auditsentinel -c "SELECT COUNT(*) FROM events;"`)
}
