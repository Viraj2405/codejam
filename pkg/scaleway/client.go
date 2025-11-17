package scaleway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPageSize = 100
	maxPages        = 500
)

// Client represents a Scaleway API client
type Client struct {
	apiKey         string
	projectID      string
	organizationID string
	apiURL         string
	httpClient     *http.Client
}

// NewClient creates a new Scaleway API client
func NewClient(apiKey, projectID, organizationID, apiURL string) *Client {
	return &Client{
		apiKey:         strings.TrimSpace(apiKey),
		projectID:      strings.TrimSpace(projectID),
		organizationID: strings.TrimSpace(organizationID),
		apiURL:         strings.TrimRight(strings.TrimSpace(apiURL), "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// AuditEvent represents a Scaleway audit trail or authentication event
type AuditEvent struct {
	ID        string
	Type      string
	Actor     string
	Resource  string
	IP        string
	Timestamp time.Time
	Source    string
	Raw       map[string]any
}

// FetchAuditEvents retrieves audit trail events from Scaleway.

func (c *Client) FetchAuditEvents(ctx context.Context, since *time.Time) ([]*AuditEvent, error) {
	if c.apiKey == "" {
		return c.mockEvents(since, "audit"), nil
	}

	return c.fetchEvents(ctx, since, "/audit/v1alpha1/events", "events", "audit")
}

// FetchAuthenticationEvents retrieves IAM authentication logs.
func (c *Client) FetchAuthenticationEvents(ctx context.Context, since *time.Time) ([]*AuditEvent, error) {
	if c.apiKey == "" {
		return c.mockEvents(since, "auth"), nil
	}

	return c.fetchEvents(ctx, since, "/iam/v1alpha1/login-logs", "login_logs", "authentication")
}

func (c *Client) fetchEvents(ctx context.Context, since *time.Time, relativePath, listKey, source string) ([]*AuditEvent, error) {
	var events []*AuditEvent
	page := 1

	for page <= maxPages {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+relativePath, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to build request: %w", err)
		}

		q := req.URL.Query()
		q.Set("page", strconv.Itoa(page))
		q.Set("page_size", strconv.Itoa(defaultPageSize))
		q.Set("order", "asc")
		q.Set("direction", "asc")
		if since != nil {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		if c.projectID != "" {
			q.Set("project_id", c.projectID)
		}
		if c.organizationID != "" {
			q.Set("organization_id", c.organizationID)
		}
		req.URL.RawQuery = q.Encode()

		c.setAuthHeaders(req)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to query Scaleway %s API: %w", source, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read Scaleway %s response: %w", source, err)
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("scaleway API authentication failed: %s", resp.Status)
		}
		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("scaleway API error (%s): %s - %s", source, resp.Status, string(body))
		}

		list, err := extractItemList(body, listKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s response: %w", source, err)
		}

		for _, raw := range list {
			event, err := mapToAuditEvent(raw)
			if err != nil {
				// Skip malformed entries but keep ingesting
				continue
			}
			if since != nil && !event.Timestamp.After(*since) {
				continue
			}
			event.Source = source
			events = append(events, event)
		}

		if len(list) < defaultPageSize {
			break
		}
		page++
	}

	return events, nil
}

func extractItemList(body []byte, listKey string) ([]map[string]any, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}

	keys := []string{listKey, "events", "items", "data"}
	for _, key := range keys {
		if raw, ok := envelope[key]; ok {
			var items []map[string]any
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, err
			}
			return items, nil
		}
	}

	// Some endpoints wrap data in "logs" or "login_logs"
	if raw, ok := envelope["logs"]; ok {
		var items []map[string]any
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, err
		}
		return items, nil
	}

	return nil, errors.New("no events found in response")
}

func mapToAuditEvent(raw map[string]any) (*AuditEvent, error) {
	id := firstString(raw, "id", "event_id", "uuid", "log_id")
	if id == "" {
		return nil, errors.New("event missing id")
	}

	eventType := firstString(raw, "event_type", "type", "category", "action")
	if eventType == "" {
		eventType = "unknown"
	}

	actor := firstString(raw, "actor", "user", "user_email", "principal", "identity")
	resource := firstString(raw, "resource", "resource_name", "target", "service_name")
	ip := firstString(raw, "ip", "ip_address", "source_ip", "client_ip")
	timestampStr := firstString(raw, "timestamp", "occurred_at", "created_at", "time", "last_login_at")

	var timestamp time.Time
	if timestampStr != "" {
		parsed, err := time.Parse(time.RFC3339, timestampStr)
		if err == nil {
			timestamp = parsed
		}
	}
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	// Ensure raw map is safe to mutate by creating a shallow copy
	rawCopy := make(map[string]any, len(raw))
	for k, v := range raw {
		rawCopy[k] = v
	}

	return &AuditEvent{
		ID:        id,
		Type:      eventType,
		Actor:     actor,
		Resource:  resource,
		IP:        ip,
		Timestamp: timestamp,
		Raw:       rawCopy,
	}, nil
}

func firstString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if val, ok := raw[key]; ok {
			switch v := val.(type) {
			case string:
				return v
			case json.Number:
				return v.String()
			case float64:
				return strconv.FormatFloat(v, 'f', -1, 64)
			case fmt.Stringer:
				return v.String()
			}
		}
	}
	return ""
}

func (c *Client) mockEvents(since *time.Time, source string) []*AuditEvent {
	now := time.Now().UTC()
	eventIDBase := now.Unix()
	mock := []*AuditEvent{
		{
			ID:        fmt.Sprintf("evt_mock_%d_001", eventIDBase),
			Type:      "auth.failed",
			Actor:     "user@example.com",
			Resource:  "iam",
			IP:        "203.0.113.1",
			Timestamp: now.Add(-10 * time.Minute),
			Source:    source,
			Raw: map[string]any{
				"event_id": fmt.Sprintf("evt_mock_%d_001", eventIDBase),
				"type":     "auth.failed",
				"actor":    "user@example.com",
				"reason":   "invalid_credentials",
			},
		},
		{
			ID:        fmt.Sprintf("evt_mock_%d_002", eventIDBase),
			Type:      "auth.failed",
			Actor:     "user@example.com",
			Resource:  "iam",
			IP:        "203.0.113.1",
			Timestamp: now.Add(-8 * time.Minute),
			Source:    source,
			Raw: map[string]any{
				"event_id": fmt.Sprintf("evt_mock_%d_002", eventIDBase),
				"type":     "auth.failed",
				"actor":    "user@example.com",
				"reason":   "invalid_credentials",
			},
		},
		{
			ID:        fmt.Sprintf("evt_mock_%d_003", eventIDBase),
			Type:      "auth.failed",
			Actor:     "user@example.com",
			Resource:  "iam",
			IP:        "203.0.113.2",
			Timestamp: now.Add(-5 * time.Minute),
			Source:    source,
			Raw: map[string]any{
				"event_id": fmt.Sprintf("evt_mock_%d_003", eventIDBase),
				"type":     "auth.failed",
				"actor":    "user@example.com",
				"reason":   "invalid_credentials",
			},
		},
		{
			ID:        fmt.Sprintf("evt_mock_%d_006", eventIDBase),
			Type:      "auth.failed",
			Actor:     "user@example.com",
			Resource:  "iam",
			IP:        "203.0.113.1",
			Timestamp: now.Add(-4 * time.Minute),
			Source:    source,
			Raw: map[string]any{
				"event_id": fmt.Sprintf("evt_mock_%d_006", eventIDBase),
				"type":     "auth.failed",
				"actor":    "user@example.com",
				"reason":   "invalid_credentials",
			},
		},
		{
			ID:        fmt.Sprintf("evt_mock_%d_007", eventIDBase),
			Type:      "auth.failed",
			Actor:     "user@example.com",
			Resource:  "iam",
			IP:        "203.0.113.3",
			Timestamp: now.Add(-2 * time.Minute),
			Source:    source,
			Raw: map[string]any{
				"event_id": fmt.Sprintf("evt_mock_%d_007", eventIDBase),
				"type":     "auth.failed",
				"actor":    "user@example.com",
				"reason":   "invalid_credentials",
			},
		},
		{
			ID:        fmt.Sprintf("evt_mock_%d_004", eventIDBase),
			Type:      "apiKey.create",
			Actor:     "admin@example.com",
			Resource:  "iam",
			IP:        "198.51.100.1",
			Timestamp: now.Add(-3 * time.Minute),
			Source:    source,
			Raw: map[string]any{
				"event_id": fmt.Sprintf("evt_mock_%d_004", eventIDBase),
				"type":     "apiKey.create",
				"actor":    "admin@example.com",
				"key_id":   "key_abc123",
				"key_name": "Production API Key",
			},
		},
		{
			ID:        fmt.Sprintf("evt_mock_%d_005", eventIDBase),
			Type:      "forbidden",
			Actor:     "attacker@example.com",
			Resource:  "secrets",
			IP:        "192.0.2.1",
			Timestamp: now.Add(-1 * time.Minute),
			Source:    source,
			Raw: map[string]any{
				"event_id": fmt.Sprintf("evt_mock_%d_005", eventIDBase),
				"type":     "forbidden",
				"actor":    "attacker@example.com",
				"resource": "secrets/database-password",
				"action":   "read",
			},
		},
	}

	if since == nil {
		return mock
	}

	var filtered []*AuditEvent
	for _, evt := range mock {
		if evt.Timestamp.After(*since) {
			filtered = append(filtered, evt)
		}
	}
	return filtered
}

// LockUser locks a user account via Scaleway IAM API
func (c *Client) LockUser(ctx context.Context, userID string) error {
	// Scaleway IAM API: Update user status to locked
	// Endpoint: PUT /iam/v1alpha1/users/{user_id}
	url := fmt.Sprintf("%s/iam/v1alpha1/users/%s", c.apiURL, userID)

	payload := map[string]interface{}{
		"status": "locked",
	}

	return c.updateUserStatus(ctx, url, payload)
}

// UnlockUser unlocks a user account via Scaleway IAM API
func (c *Client) UnlockUser(ctx context.Context, userID string) error {
	// Scaleway IAM API: Update user status to active
	// Endpoint: PUT /iam/v1alpha1/users/{user_id}
	url := fmt.Sprintf("%s/iam/v1alpha1/users/%s", c.apiURL, userID)

	payload := map[string]interface{}{
		"status": "active",
	}

	return c.updateUserStatus(ctx, url, payload)
}

// RevokeAPIKey revokes an API key via Scaleway IAM API
func (c *Client) RevokeAPIKey(ctx context.Context, keyID string) error {
	// Scaleway IAM API: Delete API key
	// Endpoint: DELETE /iam/v1alpha1/api-keys/{key_id}
	url := fmt.Sprintf("%s/iam/v1alpha1/api-keys/%s", c.apiURL, keyID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication headers
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to revoke API key: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// updateUserStatus updates user status via Scaleway IAM API
func (c *Client) updateUserStatus(ctx context.Context, url string, payload map[string]interface{}) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	c.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update user: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// setAuthHeaders sets authentication headers for Scaleway API requests
func (c *Client) setAuthHeaders(req *http.Request) {
	// Scaleway API uses X-Auth-Token header for authentication
	req.Header.Set("X-Auth-Token", c.apiKey)

	// Set project/organization ID if available
	if c.projectID != "" {
		req.Header.Set("X-Project-Id", c.projectID)
	}
	if c.organizationID != "" {
		req.Header.Set("X-Organization-Id", c.organizationID)
	}

	// Default JSON accept header
	req.Header.Set("Accept", "application/json")
}
