package main

import (
	"context"
	"log"

	"github.com/scaleway/audit-sentinel/internal/config"
	"github.com/scaleway/audit-sentinel/internal/detection"
	"github.com/scaleway/audit-sentinel/internal/storage"
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

	// Create detection storage and engine
	detectionStorage := detection.NewDetectionStorage(store.DB())
	detectionEngine := detection.NewEngine(cfg, detectionStorage)

	// Get event repository
	eventRepo := storage.NewEventRepository(store.DB())

	// Get all events from database
	ctx := context.Background()
	events, err := eventRepo.ListEvents(ctx, 100, 0, "", "")
	if err != nil {
		log.Fatalf("Failed to list events: %v", err)
	}

	log.Printf("Found %d events to process", len(events))

	// Process each event through detection engine
	processedCount := 0

	for _, event := range events {
		// Process event
		if err := detectionEngine.ProcessEvent(ctx, event); err != nil {
			log.Printf("Failed to process event %s: %v", event.EventID, err)
			continue
		}
		processedCount++
	}

	// Count alerts
	alertRepo := storage.NewAlertRepository(store.DB())
	alerts, err := alertRepo.ListAlerts(ctx, 100, 0, "", "", "")
	if err != nil {
		log.Printf("Failed to list alerts: %v", err)
	}

	log.Printf("Processed %d events", processedCount)
	log.Printf("Created %d alerts", len(alerts))
	log.Println()
	log.Println("Alerts created:")
	for _, alert := range alerts {
		log.Printf("  - %s (%s): %s", alert.AlertType, alert.Severity, alert.Description)
	}
}
