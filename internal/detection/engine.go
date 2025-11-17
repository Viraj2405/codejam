package detection

import (
	"context"

	"github.com/scaleway/audit-sentinel/internal/config"
	"github.com/scaleway/audit-sentinel/internal/models"
)

// Engine handles anomaly detection
type Engine struct {
	config  *config.Config
	rules   []Rule
	storage DetectionStorage
}


type DetectionStorage interface {
	StoreAlert(ctx context.Context, alert *models.Alert) error
	GetUserProfile(ctx context.Context, userID string) (*models.UserProfile, error)
	UpdateUserProfile(ctx context.Context, profile *models.UserProfile) error
}

// Rule defines a detection rule interface
type Rule interface {
	Name() string
	Evaluate(ctx context.Context, event *models.Event) ([]*models.Alert, error)
	IsActive() bool
}


func NewEngine(cfg *config.Config, storage DetectionStorage) *Engine {
	engine := &Engine{
		config:  cfg,
		storage: storage,
		rules:   []Rule{},
	}

	// Register default rules
	engine.registerDefaultRules()

	return engine
}


func (e *Engine) registerDefaultRules() {
	e.rules = []Rule{
		NewFailedLoginRule(e.config, e.storage),
		NewForbiddenResourceRule(e.config, e.storage),
		NewAPIKeyCreationRule(e.config, e.storage),

	}
}


func (e *Engine) ProcessEvent(ctx context.Context, event *models.Event) error {
	for _, rule := range e.rules {
		if !rule.IsActive() {
			continue
		}
		alerts, err := rule.Evaluate(ctx, event)
		if err != nil {
			// Log error but continue with other rules
			continue
		}

		// Store alerts
		for _, alert := range alerts {
			if err := e.storage.StoreAlert(ctx, alert); err != nil {
				// Log error but continue
				continue
			}
		}
	}

	return nil
}
