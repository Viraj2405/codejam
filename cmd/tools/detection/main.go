package main

import (
	"context"
	"log"

	"github.com/scaleway/audit-sentinel/internal/config"
	"github.com/scaleway/audit-sentinel/internal/detection"
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

	eventRepo := storage.NewEventRepository(store.DB())

	// Create detection storage and engine
	detectionStorage := detection.NewDetectionStorage(store.DB())
	detectionEngine := detection.NewEngine(cfg, detectionStorage)

	// Create processor
	processor := ingestion.NewProcessor(detectionEngine)

	// Create Scaleway client (mock or real)
	client := scaleway.NewClient(
		cfg.Scaleway.APIKey,
		cfg.Scaleway.ProjectID,
		cfg.Scaleway.OrganizationID,
		cfg.Scaleway.APIURL,
	)

	// Create ingestor
	ingestor := ingestion.NewIngestor(cfg, client, eventRepo)
	ingestor.SetProcessor(processor)

	// Run ingestion with detection
	ctx := context.Background()
	log.Println("Starting ingestion with detection...")

	if err := ingestor.Ingest(ctx); err != nil {
		log.Fatalf("Ingestion failed: %v", err)
	}

	log.Println("Ingestion and detection completed!")
	log.Println()
	log.Println("Check alerts in database:")
	log.Println(`psql -U auditsentinel -d auditsentinel -c "SELECT alert_type, severity, user_id, description FROM alerts;"`)
}
