package ingestion

import (
	"context"
	"log"

	"github.com/scaleway/audit-sentinel/internal/detection"
	"github.com/scaleway/audit-sentinel/internal/models"
)

// Processor handles event processing through detection engine
type Processor struct {
	detectionEngine *detection.Engine
}

// NewProcessor creates a new event processor
func NewProcessor(engine *detection.Engine) *Processor {
	return &Processor{
		detectionEngine: engine,
	}
}

// ProcessEvent processes an event through the detection engine
func (p *Processor) ProcessEvent(ctx context.Context, event *models.Event) error {
	if err := p.detectionEngine.ProcessEvent(ctx, event); err != nil {
		log.Printf("Failed to process event %s: %v", event.EventID, err)
		return err
	}
	return nil
}
