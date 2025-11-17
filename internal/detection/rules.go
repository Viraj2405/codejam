package detection

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/scaleway/audit-sentinel/internal/config"
	"github.com/scaleway/audit-sentinel/internal/models"
)

// FailedLoginRule detects brute force login attempts
type FailedLoginRule struct {
	config  *config.Config
	storage DetectionStorage
	db      *sql.DB
}

func NewFailedLoginRule(cfg *config.Config, storage DetectionStorage) *FailedLoginRule {
	impl := storage.(*DetectionStorageImpl)
	return &FailedLoginRule{
		config:  cfg,
		storage: storage,
		db:      impl.db,
	}
}

func (r *FailedLoginRule) Name() string {
	return "failed_login_spike"
}

func (r *FailedLoginRule) IsActive() bool {
	return true
}

func (r *FailedLoginRule) Evaluate(ctx context.Context, event *models.Event) ([]*models.Alert, error) {
	// Only process auth.failed events
	if event.EventType != "auth.failed" {
		return nil, nil
	}

	// Skip if no actor
	if event.Actor == "" {
		return nil, nil
	}

	// Count failed login attempts in the time window
	windowMinutes := r.config.Detection.FailedLoginWindowMin
	threshold := r.config.Detection.FailedLoginThreshold

	query := fmt.Sprintf(`
		SELECT COUNT(*) as failed_count, 
		       array_agg(id ORDER BY timestamp)::text as event_ids,
		       array_agg(ip ORDER BY timestamp)::text as ip_addresses
		FROM events
		WHERE actor = $1
		  AND event_type = 'auth.failed'
		  AND timestamp > NOW() - INTERVAL '%d minutes'
	`, windowMinutes)

	var failedCount int
	var eventIDsStr sql.NullString
	var ipAddressesStr sql.NullString

	err := r.db.QueryRowContext(ctx, query, event.Actor).Scan(&failedCount, &eventIDsStr, &ipAddressesStr)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query failed logins: %w", err)
	}

	eventIDsStrVal := ""
	if eventIDsStr.Valid {
		eventIDsStrVal = eventIDsStr.String
	}
	ipAddressesStrVal := ""
	if ipAddressesStr.Valid {
		ipAddressesStrVal = ipAddressesStr.String
	}

	if failedCount >= threshold {

		eventIDs := parseUUIDArray(eventIDsStrVal)
		if len(eventIDs) == 0 {
			eventIDs = []uuid.UUID{event.ID}
		}

		ipAddresses := parseStringArray(ipAddressesStrVal)
		if len(ipAddresses) == 0 {
			ipAddresses = []string{event.IP}
		}

		alert := &models.Alert{
			ID:          uuid.New(),
			EventRefs:   eventIDs,
			AlertType:   r.Name(),
			Severity:    models.SeverityHigh,
			UserID:      event.Actor,
			Description: fmt.Sprintf("Detected %d failed login attempts for user %s within %d minutes (threshold: %d)", failedCount, event.Actor, windowMinutes, threshold),
			Status:      models.AlertStatusOpen,
			Evidence: map[string]any{
				"failed_attempts": failedCount,
				"window_minutes":  windowMinutes,
				"threshold":       threshold,
				"ip_addresses":    ipAddresses,
				"first_attempt":   event.Timestamp.Format(time.RFC3339),
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		return []*models.Alert{alert}, nil
	}

	return nil, nil
}

type ForbiddenResourceRule struct {
	config  *config.Config
	storage DetectionStorage
	db      *sql.DB
}

func NewForbiddenResourceRule(cfg *config.Config, storage DetectionStorage) *ForbiddenResourceRule {
	impl := storage.(*DetectionStorageImpl)
	return &ForbiddenResourceRule{
		config:  cfg,
		storage: storage,
		db:      impl.db,
	}
}

func (r *ForbiddenResourceRule) Name() string {
	return "forbidden_sensitive_resource"
}

func (r *ForbiddenResourceRule) IsActive() bool {
	return true
}

func (r *ForbiddenResourceRule) Evaluate(ctx context.Context, event *models.Event) ([]*models.Alert, error) {
	// Check if event is a forbidden action
	if event.EventType != "forbidden" {
		return nil, nil
	}

	// Define sensitive resource types
	sensitiveResources := []string{"iam", "secrets", "kms", "secret"}
	isSensitive := false
	resourceType := ""

	// Check if resource is sensitive
	for _, sensitive := range sensitiveResources {
		if event.Resource != "" && contains(event.Resource, sensitive) {
			isSensitive = true
			resourceType = sensitive
			break
		}
		// Also check in raw data
		if rawResource, ok := event.Raw["resource"].(string); ok && contains(rawResource, sensitive) {
			isSensitive = true
			resourceType = sensitive
			break
		}
	}

	if !isSensitive {
		return nil, nil
	}

	// Create CRITICAL alert for forbidden access to sensitive resource
	alert := &models.Alert{
		ID:          uuid.New(),
		EventRefs:   []uuid.UUID{event.ID},
		AlertType:   r.Name(),
		Severity:    models.SeverityCritical,
		UserID:      event.Actor,
		Description: fmt.Sprintf("Forbidden access attempt to sensitive resource (%s) by %s", resourceType, event.Actor),
		Status:      models.AlertStatusOpen,
		Evidence: map[string]any{
			"resource_type": resourceType,
			"resource":      event.Resource,
			"ip_address":    event.IP,
			"timestamp":     event.Timestamp.Format(time.RFC3339),
			"raw_event":     event.Raw,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return []*models.Alert{alert}, nil
}

// APIKeyCreationRule detects new API key creation
type APIKeyCreationRule struct {
	config  *config.Config
	storage DetectionStorage
	db      *sql.DB
}

func NewAPIKeyCreationRule(cfg *config.Config, storage DetectionStorage) *APIKeyCreationRule {
	impl := storage.(*DetectionStorageImpl)
	return &APIKeyCreationRule{
		config:  cfg,
		storage: storage,
		db:      impl.db,
	}
}

func (r *APIKeyCreationRule) Name() string {
	return "api_key_creation"
}

func (r *APIKeyCreationRule) IsActive() bool {
	return true
}

func (r *APIKeyCreationRule) Evaluate(ctx context.Context, event *models.Event) ([]*models.Alert, error) {
	// Check if event is API key creation
	if event.EventType != "apiKey.create" {
		return nil, nil
	}

	// Extract API key information from raw event
	keyID := ""
	keyName := ""
	if rawKeyID, ok := event.Raw["key_id"].(string); ok {
		keyID = rawKeyID
	}
	if rawKeyName, ok := event.Raw["key_name"].(string); ok {
		keyName = rawKeyName
	}

	// Create HIGH severity alert for API key creation
	alert := &models.Alert{
		ID:          uuid.New(),
		EventRefs:   []uuid.UUID{event.ID},
		AlertType:   r.Name(),
		Severity:    models.SeverityHigh,
		UserID:      event.Actor,
		Description: fmt.Sprintf("New API key created by %s", event.Actor),
		Status:      models.AlertStatusOpen,
		Evidence: map[string]any{
			"key_id":     keyID,
			"key_name":   keyName,
			"ip_address": event.IP,
			"timestamp":  event.Timestamp.Format(time.RFC3339),
			"raw_event":  event.Raw,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return []*models.Alert{alert}, nil
}

// UnusualIPRule detects access from unusual IP/region
type UnusualIPRule struct {
	config  *config.Config
	storage DetectionStorage
}

func NewUnusualIPRule(cfg *config.Config, storage DetectionStorage) *UnusualIPRule {
	return &UnusualIPRule{config: cfg, storage: storage}
}

func (r *UnusualIPRule) Name() string {
	return "unusual_ip_region"
}

func (r *UnusualIPRule) IsActive() bool {
	return true
}

func (r *UnusualIPRule) Evaluate(ctx context.Context, event *models.Event) ([]*models.Alert, error) {

	return nil, nil
}

type ImpossibleTravelRule struct {
	config  *config.Config
	storage DetectionStorage
}

func NewImpossibleTravelRule(cfg *config.Config, storage DetectionStorage) *ImpossibleTravelRule {
	return &ImpossibleTravelRule{config: cfg, storage: storage}
}

func (r *ImpossibleTravelRule) Name() string {
	return "impossible_travel"
}

func (r *ImpossibleTravelRule) IsActive() bool {
	return true
}

func (r *ImpossibleTravelRule) Evaluate(ctx context.Context, event *models.Event) ([]*models.Alert, error) {

	return nil, nil
}

// IAMPolicyChangeRule detects IAM policy changes
type IAMPolicyChangeRule struct {
	config  *config.Config
	storage DetectionStorage
}

func NewIAMPolicyChangeRule(cfg *config.Config, storage DetectionStorage) *IAMPolicyChangeRule {
	return &IAMPolicyChangeRule{config: cfg, storage: storage}
}

func (r *IAMPolicyChangeRule) Name() string {
	return "iam_policy_change"
}

func (r *IAMPolicyChangeRule) IsActive() bool {
	return true
}

func (r *IAMPolicyChangeRule) Evaluate(ctx context.Context, event *models.Event) ([]*models.Alert, error) {

	return nil, nil
}

// HighPrivilegeUnknownIPRule detects high privilege actions from unknown IPs
type HighPrivilegeUnknownIPRule struct {
	config  *config.Config
	storage DetectionStorage
}

func NewHighPrivilegeUnknownIPRule(cfg *config.Config, storage DetectionStorage) *HighPrivilegeUnknownIPRule {
	return &HighPrivilegeUnknownIPRule{config: cfg, storage: storage}
}

func (r *HighPrivilegeUnknownIPRule) Name() string {
	return "high_privilege_unknown_ip"
}

func (r *HighPrivilegeUnknownIPRule) IsActive() bool {
	return true
}

func (r *HighPrivilegeUnknownIPRule) Evaluate(ctx context.Context, event *models.Event) ([]*models.Alert, error) {

	return nil, nil
}

// Helper functions

// parseUUIDArray parses PostgreSQL array string into UUID slice
func parseUUIDArray(str string) []uuid.UUID {
	if str == "" || str == "{}" {
		return []uuid.UUID{}
	}

	// Remove curly braces
	str = str[1 : len(str)-1]
	if str == "" {
		return []uuid.UUID{}
	}

	parts := splitArrayString(str)
	uuids := make([]uuid.UUID, 0, len(parts))
	for _, part := range parts {
		part = trimQuotes(part)
		if part == "" {
			continue
		}
		u, err := uuid.Parse(part)
		if err != nil {
			continue
		}
		uuids = append(uuids, u)
	}
	return uuids
}

// parseStringArray parses PostgreSQL array string into string slice
func parseStringArray(str string) []string {
	if str == "" || str == "{}" {
		return []string{}
	}

	// Remove curly braces
	str = str[1 : len(str)-1]
	if str == "" {
		return []string{}
	}

	parts := splitArrayString(str)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = trimQuotes(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// splitArrayString splits PostgreSQL array string handling quoted values
func splitArrayString(s string) []string {
	var result []string
	var current strings.Builder
	inQuotes := false

	for i := 0; i < len(s); i++ {
		char := s[i]
		if char == '"' {
			inQuotes = !inQuotes
			current.WriteByte(char)
		} else if char == ',' && !inQuotes {
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(char)
		}
	}
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result
}

// trimQuotes removes surrounding quotes from string
func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// contains checks if string contains substring (case-insensitive)
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
