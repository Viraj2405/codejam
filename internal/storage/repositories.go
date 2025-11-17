package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/scaleway/audit-sentinel/internal/models"
)

// EventRepository implements event storage operations
type EventRepository struct {
	db *sql.DB
}

// NewEventRepository creates a new event repository
func NewEventRepository(db *sql.DB) *EventRepository {
	return &EventRepository{db: db}
}

// StoreEvent stores an event in the database
func (r *EventRepository) StoreEvent(ctx context.Context, event *models.Event) error {
	rawJSON, err := json.Marshal(event.Raw)
	if err != nil {
		return fmt.Errorf("failed to marshal raw event: %w", err)
	}

	query := `
		INSERT INTO events (id, event_id, raw, event_type, actor, resource, ip, region, timestamp, ingest_failed, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (event_id) DO NOTHING
	`

	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}

	_, err = r.db.ExecContext(ctx, query,
		event.ID,
		event.EventID,
		rawJSON,
		event.EventType,
		event.Actor,
		event.Resource,
		event.IP,
		event.Region,
		event.Timestamp,
		event.IngestFailed,
		event.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	return nil
}

// GetLastEventTimestamp gets the timestamp of the most recent event
func (r *EventRepository) GetLastEventTimestamp(ctx context.Context) (*time.Time, error) {
	var timestamp sql.NullTime
	err := r.db.QueryRowContext(ctx, "SELECT MAX(timestamp) FROM events").Scan(&timestamp)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get last event timestamp: %w", err)
	}
	if !timestamp.Valid {
		return nil, nil
	}
	return &timestamp.Time, nil
}

// EventExists checks if an event with the given event_id exists
func (r *EventRepository) EventExists(ctx context.Context, eventID string) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE event_id = $1", eventID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check event existence: %w", err)
	}
	return count > 0, nil
}

// GetEventByID retrieves an event by its database ID
func (r *EventRepository) GetEventByID(ctx context.Context, id uuid.UUID) (*models.Event, error) {
	var event models.Event
	var rawJSON []byte

	query := `
		SELECT id, event_id, raw, event_type, actor, resource, ip, region, timestamp, ingest_failed, created_at
		FROM events
		WHERE id = $1
	`

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&event.ID,
		&event.EventID,
		&rawJSON,
		&event.EventType,
		&event.Actor,
		&event.Resource,
		&event.IP,
		&event.Region,
		&event.Timestamp,
		&event.IngestFailed,
		&event.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("event not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get event: %w", err)
	}

	if err := json.Unmarshal(rawJSON, &event.Raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal raw event: %w", err)
	}

	return &event, nil
}

// ListEvents retrieves events with optional filters
func (r *EventRepository) ListEvents(ctx context.Context, limit, offset int, eventType, actor string) ([]*models.Event, error) {
	query := `
		SELECT id, event_id, raw, event_type, actor, resource, ip, region, timestamp, ingest_failed, created_at
		FROM events
		WHERE 1=1
	`
	args := []interface{}{}
	argPos := 1

	if eventType != "" {
		query += fmt.Sprintf(" AND event_type = $%d", argPos)
		args = append(args, eventType)
		argPos++
	}

	if actor != "" {
		query += fmt.Sprintf(" AND actor = $%d", argPos)
		args = append(args, actor)
		argPos++
	}

	query += " ORDER BY timestamp DESC LIMIT $" + fmt.Sprintf("%d", argPos) + " OFFSET $" + fmt.Sprintf("%d", argPos+1)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []*models.Event
	for rows.Next() {
		var event models.Event
		var rawJSON []byte

		err := rows.Scan(
			&event.ID,
			&event.EventID,
			&rawJSON,
			&event.EventType,
			&event.Actor,
			&event.Resource,
			&event.IP,
			&event.Region,
			&event.Timestamp,
			&event.IngestFailed,
			&event.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}

		if err := json.Unmarshal(rawJSON, &event.Raw); err != nil {
			return nil, fmt.Errorf("failed to unmarshal raw event: %w", err)
		}

		events = append(events, &event)
	}

	return events, nil
}

// AlertRepository implements alert storage operations
type AlertRepository struct {
	db *sql.DB
}

// NewAlertRepository creates a new alert repository
func NewAlertRepository(db *sql.DB) *AlertRepository {
	return &AlertRepository{db: db}
}

// StoreAlert stores an alert in the database
func (r *AlertRepository) StoreAlert(ctx context.Context, alert *models.Alert) error {
	evidenceJSON, err := json.Marshal(alert.Evidence)
	if err != nil {
		return fmt.Errorf("failed to marshal evidence: %w", err)
	}

	query := `
		INSERT INTO alerts (id, event_refs, alert_type, severity, user_id, description, status, evidence, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	if alert.ID == uuid.Nil {
		alert.ID = uuid.New()
	}
	if alert.CreatedAt.IsZero() {
		alert.CreatedAt = time.Now()
	}
	if alert.UpdatedAt.IsZero() {
		alert.UpdatedAt = time.Now()
	}
	if alert.Status == "" {
		alert.Status = models.AlertStatusOpen
	}

	// Convert UUID array to PostgreSQL array format
	eventRefsArray := pqArray(alert.EventRefs)

	_, err = r.db.ExecContext(ctx, query,
		alert.ID,
		eventRefsArray,
		alert.AlertType,
		alert.Severity,
		alert.UserID,
		alert.Description,
		alert.Status,
		evidenceJSON,
		alert.CreatedAt,
		alert.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store alert: %w", err)
	}

	return nil
}

// GetAlert retrieves an alert by ID
func (r *AlertRepository) GetAlert(ctx context.Context, id uuid.UUID) (*models.Alert, error) {
	var alert models.Alert
	var evidenceJSON []byte
	var eventRefs []uuid.UUID

	query := `
		SELECT id, event_refs, alert_type, severity, user_id, description, status, evidence, created_at, updated_at
		FROM alerts
		WHERE id = $1
	`

	var eventRefsStr string
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&alert.ID,
		&eventRefsStr,
		&alert.AlertType,
		&alert.Severity,
		&alert.UserID,
		&alert.Description,
		&alert.Status,
		&evidenceJSON,
		&alert.CreatedAt,
		&alert.UpdatedAt,
	)
	if err == nil {
		eventRefs = parseUUIDArray(eventRefsStr)
	}
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("alert not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get alert: %w", err)
	}

	alert.EventRefs = eventRefs
	if err := json.Unmarshal(evidenceJSON, &alert.Evidence); err != nil {
		return nil, fmt.Errorf("failed to unmarshal evidence: %w", err)
	}

	return &alert, nil
}

// ListAlerts retrieves alerts with optional filters
func (r *AlertRepository) ListAlerts(ctx context.Context, limit, offset int, severity, status, userID string) ([]*models.Alert, error) {
	query := `
		SELECT id, event_refs, alert_type, severity, user_id, description, status, evidence, created_at, updated_at
		FROM alerts
		WHERE 1=1
	`
	args := []interface{}{}
	argPos := 1

	if severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argPos)
		args = append(args, severity)
		argPos++
	}

	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argPos)
		args = append(args, status)
		argPos++
	}

	if userID != "" {
		query += fmt.Sprintf(" AND user_id = $%d", argPos)
		args = append(args, userID)
		argPos++
	}

	query += " ORDER BY created_at DESC LIMIT $" + fmt.Sprintf("%d", argPos) + " OFFSET $" + fmt.Sprintf("%d", argPos+1)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query alerts: %w", err)
	}
	defer rows.Close()

	var alerts []*models.Alert
	for rows.Next() {
		var alert models.Alert
		var evidenceJSON []byte
		var eventRefsStr string
		err := rows.Scan(
			&alert.ID,
			&eventRefsStr,
			&alert.AlertType,
			&alert.Severity,
			&alert.UserID,
			&alert.Description,
			&alert.Status,
			&evidenceJSON,
			&alert.CreatedAt,
			&alert.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan alert: %w", err)
		}

		alert.EventRefs = parseUUIDArray(eventRefsStr)
		if err := json.Unmarshal(evidenceJSON, &alert.Evidence); err != nil {
			return nil, fmt.Errorf("failed to unmarshal evidence: %w", err)
		}

		alerts = append(alerts, &alert)
	}

	return alerts, nil
}

// UpdateAlertStatus updates an alert's status
func (r *AlertRepository) UpdateAlertStatus(ctx context.Context, id uuid.UUID, status models.AlertStatus) error {
	query := `UPDATE alerts SET status = $1, updated_at = $2 WHERE id = $3`
	_, err := r.db.ExecContext(ctx, query, status, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update alert status: %w", err)
	}
	return nil
}

// RemediationRepository implements remediation log storage
type RemediationRepository struct {
	db *sql.DB
}

// NewRemediationRepository creates a new remediation repository
func NewRemediationRepository(db *sql.DB) *RemediationRepository {
	return &RemediationRepository{db: db}
}

// LogRemediation stores a remediation action log
func (r *RemediationRepository) LogRemediation(ctx context.Context, logEntry *models.RemediationLog) error {
	payloadJSON, err := json.Marshal(logEntry.Payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	query := `
		INSERT INTO remediation_logs (id, alert_id, actor_user, action_type, payload, result, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	if logEntry.ID == uuid.Nil {
		logEntry.ID = uuid.New()
	}
	if logEntry.Timestamp.IsZero() {
		logEntry.Timestamp = time.Now()
	}

	_, err = r.db.ExecContext(ctx, query,
		logEntry.ID,
		logEntry.AlertID,
		logEntry.ActorUser,
		logEntry.ActionType,
		payloadJSON,
		logEntry.Result,
		logEntry.Timestamp,
	)
	if err != nil {
		return fmt.Errorf("failed to log remediation: %w", err)
	}

	return nil
}

// GetRemediationLogs retrieves remediation logs for an alert
func (r *RemediationRepository) GetRemediationLogs(ctx context.Context, alertID uuid.UUID) ([]*models.RemediationLog, error) {
	query := `
		SELECT id, alert_id, actor_user, action_type, payload, result, timestamp
		FROM remediation_logs
		WHERE alert_id = $1
		ORDER BY timestamp DESC
	`

	rows, err := r.db.QueryContext(ctx, query, alertID)
	if err != nil {
		return nil, fmt.Errorf("failed to query remediation logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.RemediationLog
	for rows.Next() {
		var logEntry models.RemediationLog
		var payloadJSON []byte

		err := rows.Scan(
			&logEntry.ID,
			&logEntry.AlertID,
			&logEntry.ActorUser,
			&logEntry.ActionType,
			&payloadJSON,
			&logEntry.Result,
			&logEntry.Timestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan remediation log: %w", err)
		}

		if err := json.Unmarshal(payloadJSON, &logEntry.Payload); err != nil {
			return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
		}

		logs = append(logs, &logEntry)
	}

	return logs, nil
}

// Helper functions for PostgreSQL array handling
func pqArray(uuids []uuid.UUID) string {
	if len(uuids) == 0 {
		return "{}"
	}
	strs := make([]string, len(uuids))
	for i, u := range uuids {
		strs[i] = fmt.Sprintf(`"%s"`, u.String())
	}
	return fmt.Sprintf("{%s}", strings.Join(strs, ","))
}

func parseUUIDArray(str string) []uuid.UUID {
	// Remove curly braces
	str = strings.Trim(str, "{}")
	if str == "" {
		return []uuid.UUID{}
	}

	parts := strings.Split(str, ",")
	uuids := make([]uuid.UUID, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"`)
		if part == "" {
			continue
		}
		u, err := uuid.Parse(part)
		if err != nil {
			continue // Skip invalid UUIDs
		}
		uuids = append(uuids, u)
	}

	return uuids
}
