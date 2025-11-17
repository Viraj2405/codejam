package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/scaleway/audit-sentinel/internal/config"
	"github.com/scaleway/audit-sentinel/internal/models"
	"github.com/scaleway/audit-sentinel/internal/storage"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	store, err := storage.NewStorage(cfg.Database.URL)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Test Event Repository
	fmt.Println("=== Testing Event Repository ===")
	eventRepo := storage.NewEventRepository(store.DB())

	// Create test event
	testEvent := &models.Event{
		ID:           uuid.New(),
		EventID:      "test_event_001",
		EventType:    "test.type",
		Actor:        "test@example.com",
		Resource:     "test-resource",
		IP:           "127.0.0.1",
		Region:       "test-region",
		Timestamp:    time.Now(),
		IngestFailed: false,
		CreatedAt:    time.Now(),
		Raw: map[string]any{
			"test": "data",
		},
	}

	// Store event
	if err := eventRepo.StoreEvent(ctx, testEvent); err != nil {
		log.Fatalf("Failed to store event: %v", err)
	}
	fmt.Println("Event stored successfully")

	// Check if exists
	exists, err := eventRepo.EventExists(ctx, "test_event_001")
	if err != nil {
		log.Fatalf("Failed to check event: %v", err)
	}
	fmt.Printf("Event exists check: %v\n", exists)

	// Get last timestamp
	lastTs, err := eventRepo.GetLastEventTimestamp(ctx)
	if err != nil {
		log.Fatalf("Failed to get last timestamp: %v", err)
	}
	if lastTs != nil {
		fmt.Printf("Last event timestamp: %v\n", lastTs)
	}

	// Test Alert Repository
	fmt.Println("\n=== Testing Alert Repository ===")
	alertRepo := storage.NewAlertRepository(store.DB())

	testAlert := &models.Alert{
		ID:          uuid.New(),
		EventRefs:   []uuid.UUID{testEvent.ID},
		AlertType:   "test_alert",
		Severity:    models.SeverityHigh,
		UserID:      "test@example.com",
		Description: "Test alert",
		Status:      models.AlertStatusOpen,
		Evidence: map[string]any{
			"count": 5,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := alertRepo.StoreAlert(ctx, testAlert); err != nil {
		log.Fatalf("Failed to store alert: %v", err)
	}
	fmt.Println("Alert stored successfully")

	// Retrieve alert
	retrieved, err := alertRepo.GetAlert(ctx, testAlert.ID)
	if err != nil {
		log.Fatalf("Failed to get alert: %v", err)
	}
	fmt.Printf("Alert retrieved: %s - %s\n", retrieved.AlertType, retrieved.Severity)

	// List alerts
	alerts, err := alertRepo.ListAlerts(ctx, 10, 0, "", "", "")
	if err != nil {
		log.Fatalf("Failed to list alerts: %v", err)
	}
	fmt.Printf("Found %d alerts\n", len(alerts))

	// Test Remediation Repository
	fmt.Println("\n=== Testing Remediation Repository ===")
	remediationRepo := storage.NewRemediationRepository(store.DB())

	remediationLog := &models.RemediationLog{
		ID:         uuid.New(),
		AlertID:    testAlert.ID,
		ActorUser:  "admin@example.com",
		ActionType: models.ActionTypeLockUser,
		Payload: map[string]any{
			"user_id": "test@example.com",
			"reason":  "Test remediation",
		},
		Result:    "success",
		Timestamp: time.Now(),
	}

	if err := remediationRepo.LogRemediation(ctx, remediationLog); err != nil {
		log.Fatalf("Failed to log remediation: %v", err)
	}
	fmt.Println("Remediation logged successfully")

	fmt.Println("\nAll repository tests passed!")
}
