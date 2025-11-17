package models

import (
	"time"

	"github.com/google/uuid"
)

// Event represents a Scaleway audit trail event
type Event struct {
	ID           uuid.UUID      `json:"id" db:"id"`
	EventID      string         `json:"event_id" db:"event_id"`
	Raw          map[string]any `json:"raw" db:"raw"`
	EventType    string         `json:"event_type" db:"event_type"`
	Actor        string         `json:"actor" db:"actor"`
	Resource     string         `json:"resource" db:"resource"`
	IP           string         `json:"ip" db:"ip"`
	Region       string         `json:"region" db:"region"`
	Timestamp    time.Time      `json:"timestamp" db:"timestamp"`
	IngestFailed bool           `json:"ingest_failed" db:"ingest_failed"`
	CreatedAt    time.Time      `json:"created_at" db:"created_at"`
}

// Alert represents a security alert
type Alert struct {
	ID          uuid.UUID      `json:"id" db:"id"`
	EventRefs   []uuid.UUID    `json:"event_refs" db:"event_refs"`
	AlertType   string         `json:"alert_type" db:"alert_type"`
	Severity    Severity       `json:"severity" db:"severity"`
	UserID      string         `json:"user_id" db:"user_id"`
	Description string         `json:"description" db:"description"`
	Status      AlertStatus    `json:"status" db:"status"`
	Evidence    map[string]any `json:"evidence" db:"evidence"`
	CreatedAt   time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
}

// Severity represents alert severity level
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// AlertStatus represents alert status
type AlertStatus string

const (
	AlertStatusOpen          AlertStatus = "OPEN"
	AlertStatusInvestigating AlertStatus = "INVESTIGATING"
	AlertStatusResolved      AlertStatus = "RESOLVED"
	AlertStatusFalsePositive AlertStatus = "FALSE_POSITIVE"
)

// RemediationLog represents a remediation action
type RemediationLog struct {
	ID         uuid.UUID      `json:"id" db:"id"`
	AlertID    uuid.UUID      `json:"alert_id" db:"alert_id"`
	ActorUser  string         `json:"actor_user" db:"actor_user"`
	ActionType ActionType     `json:"action_type" db:"action_type"`
	Payload    map[string]any `json:"payload" db:"payload"`
	Result     string         `json:"result" db:"result"`
	Timestamp  time.Time      `json:"timestamp" db:"timestamp"`
}

// ActionType represents remediation action type
type ActionType string

const (
	ActionTypeLockUser   ActionType = "lock_user"
	ActionTypeUnlockUser ActionType = "unlock_user"
	ActionTypeRevokeKey  ActionType = "revoke_key"
)

// UserProfile represents a user risk profile
type UserProfile struct {
	ID             uuid.UUID `json:"id" db:"id"`
	ScalewayUserID string    `json:"scaleway_user_id" db:"scaleway_user_id"`
	LastSeenIP     string    `json:"last_seen_ip" db:"last_seen_ip"`
	LastSeenRegion string    `json:"last_seen_region" db:"last_seen_region"`
	RiskScore      int       `json:"risk_score" db:"risk_score"`
	Locked         bool      `json:"locked" db:"locked"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// Rule represents a detection rule
type Rule struct {
	ID          uuid.UUID      `json:"id" db:"id"`
	Name        string         `json:"name" db:"name"`
	Description string         `json:"description" db:"description"`
	Params      map[string]any `json:"params" db:"params"`
	Active      bool           `json:"active" db:"active"`
	CreatedAt   time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
}
