package ingestion

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/scaleway/audit-sentinel/internal/config"
	"github.com/scaleway/audit-sentinel/internal/models"
	"github.com/scaleway/audit-sentinel/pkg/scaleway"
)

// Ingestor handles event ingestion from Scaleway API
type Ingestor struct {
	config     *config.Config
	client     *scaleway.Client
	repository EventRepository
	processor  EventProcessor
}

// EventProcessor defines the interface for event processing
type EventProcessor interface {
	ProcessEvent(ctx context.Context, event *models.Event) error
}

// EventRepository defines the interface for event storage
type EventRepository interface {
	StoreEvent(ctx context.Context, event *models.Event) error
	GetLastEventTimestamp(ctx context.Context) (*time.Time, error)
	EventExists(ctx context.Context, eventID string) (bool, error)
}

// Event represents an ingested event
type Event struct {
	EventID   string
	Raw       map[string]any
	EventType string
	Actor     string
	Resource  string
	IP        string
	Region    string
	Timestamp time.Time
}

// NewIngestor creates a new event ingestor
func NewIngestor(cfg *config.Config, client *scaleway.Client, repo EventRepository) *Ingestor {
	return &Ingestor{
		config:     cfg,
		client:     client,
		repository: repo,
		processor:  nil, 
	}
}

// SetProcessor sets the event processor for detection
func (i *Ingestor) SetProcessor(processor EventProcessor) {
	i.processor = processor
}

// Start begins periodic ingestion
func (i *Ingestor) Start(ctx context.Context) error {
	ticker := time.NewTicker(time.Duration(i.config.Ingestion.PollIntervalSeconds) * time.Second)
	defer ticker.Stop()

	// Initial ingestion
	if err := i.Ingest(ctx); err != nil {
		log.Printf("Initial ingestion failed: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := i.Ingest(ctx); err != nil {
				log.Printf("Ingestion failed: %v", err)
			}
		}
	}
}

// Ingest fetches and stores events from Scaleway API
func (i *Ingestor) Ingest(ctx context.Context) error {
	log.Println("Starting event ingestion...")

	// Get last event timestamp to determine fetch window
	lastTimestamp, err := i.repository.GetLastEventTimestamp(ctx)
	if err != nil {
		log.Printf("Failed to get last event timestamp: %v", err)
		// Continue with default window
	}

	// Fetch audit trail events
	auditEvents, err := i.client.FetchAuditEvents(ctx, lastTimestamp)
	if err != nil {
		return fmt.Errorf("failed to fetch audit events: %w", err)
	}

	// Fetch authentication events
	authEvents, err := i.client.FetchAuthenticationEvents(ctx, lastTimestamp)
	if err != nil {
		return fmt.Errorf("failed to fetch authentication events: %w", err)
	}

	log.Printf("Fetched %d audit events and %d authentication events from Scaleway API", len(auditEvents), len(authEvents))

	events := make([]*scaleway.AuditEvent, 0, len(auditEvents)+len(authEvents))
	events = append(events, auditEvents...)
	events = append(events, authEvents...)
	if len(events) == 0 {
		log.Println("No new events to ingest")
		return nil
	}

	// Process and store events
	for _, scalewayEvent := range events {
		// Check for duplicates
		exists, err := i.repository.EventExists(ctx, scalewayEvent.ID)
		if err != nil {
			log.Printf("Error checking event existence: %v", err)
			continue
		}
		if exists {
			continue
		}

		// Ensure raw map exists and annotate source for downstream consumers
		if scalewayEvent.Raw == nil {
			scalewayEvent.Raw = map[string]any{}
		}
		if scalewayEvent.Source != "" {
			scalewayEvent.Raw["source"] = scalewayEvent.Source
		}

		// Convert Scaleway event to ingestion event
		event := &Event{
			EventID:   scalewayEvent.ID,
			Raw:       scalewayEvent.Raw,
			EventType: scalewayEvent.Type,
			Actor:     scalewayEvent.Actor,
			Resource:  scalewayEvent.Resource,
			IP:        scalewayEvent.IP,
			Timestamp: scalewayEvent.Timestamp,
		}

		// Enrich event (geo IP, etc.)
		enrichedEvent := i.enrichEvent(event)

		// Convert to models.Event for storage
		modelEvent := &models.Event{
			ID:           uuid.New(),
			EventID:      enrichedEvent.EventID,
			Raw:          enrichedEvent.Raw,
			EventType:    enrichedEvent.EventType,
			Actor:        enrichedEvent.Actor,
			Resource:     enrichedEvent.Resource,
			IP:           enrichedEvent.IP,
			Region:       enrichedEvent.Region,
			Timestamp:    enrichedEvent.Timestamp,
			IngestFailed: false,
			CreatedAt:    time.Now(),
		}

		// Store event
		if err := i.repository.StoreEvent(ctx, modelEvent); err != nil {
			log.Printf("Failed to store event %s: %v", scalewayEvent.ID, err)
			continue
		}

		// Process event through detection engine (if available)
		if i.processor != nil {
			if err := i.processor.ProcessEvent(ctx, modelEvent); err != nil {
				log.Printf("Failed to process event %s through detection: %v", scalewayEvent.ID, err)
				// Continue even if detection fails
			}
		}
	}

	log.Printf("Ingestion completed: %d events processed", len(events))
	return nil
}

// enrichEvent enriches event with additional data (geo IP, etc.)
func (i *Ingestor) enrichEvent(event *Event) *Event {

	return event
}
