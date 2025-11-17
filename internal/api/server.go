package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/scaleway/audit-sentinel/internal/config"
	"github.com/scaleway/audit-sentinel/internal/detection"
	"github.com/scaleway/audit-sentinel/internal/ingestion"
	"github.com/scaleway/audit-sentinel/internal/models"
	"github.com/scaleway/audit-sentinel/internal/remediation"
	"github.com/scaleway/audit-sentinel/internal/storage"
	"github.com/scaleway/audit-sentinel/pkg/scaleway"
)

// Server represents the HTTP API server
type Server struct {
	config          *config.Config
	router          *mux.Router
	httpServer      *http.Server
	storage         *storage.Storage
	eventRepo       *storage.EventRepository
	alertRepo       *storage.AlertRepository
	remediationRepo *storage.RemediationRepository
	ingestor        *ingestion.Ingestor
	remediationSvc  *remediation.Service
}

// NewServer creates a new API server instance
func NewServer(cfg *config.Config) (*Server, error) {
	// Initialize storage
	store, err := storage.NewStorage(cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Create repositories
	eventRepo := storage.NewEventRepository(store.DB())
	alertRepo := storage.NewAlertRepository(store.DB())
	remediationRepo := storage.NewRemediationRepository(store.DB())

	// Create Scaleway client
	scalewayClient := scaleway.NewClient(
		cfg.Scaleway.APIKey,
		cfg.Scaleway.ProjectID,
		cfg.Scaleway.OrganizationID,
		cfg.Scaleway.APIURL,
	)

	// Create detection engine
	detectionStorage := detection.NewDetectionStorage(store.DB())
	detectionEngine := detection.NewEngine(cfg, detectionStorage)

	// Create ingestion processor
	processor := ingestion.NewProcessor(detectionEngine)

	// Create ingestor
	ingestor := ingestion.NewIngestor(cfg, scalewayClient, eventRepo)
	ingestor.SetProcessor(processor)

	// Create remediation repository adapter
	remediationRepoAdapter := &remediationRepositoryAdapter{
		alertRepo:       alertRepo,
		remediationRepo: remediationRepo,
	}

	// Create remediation service
	remediationSvc := remediation.NewService(cfg, scalewayClient, remediationRepoAdapter)

	router := mux.NewRouter()

	corsMiddleware := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete, http.MethodOptions}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "Accept"}),
	)

	server := &Server{
		config:          cfg,
		router:          router,
		storage:         store,
		eventRepo:       eventRepo,
		alertRepo:       alertRepo,
		remediationRepo: remediationRepo,
		ingestor:        ingestor,
		remediationSvc:  remediationSvc,
		httpServer: &http.Server{
			Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
			Handler:      corsMiddleware(router),
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}

	server.setupRoutes()
	return server, nil
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	api := s.router.PathPrefix(s.config.Server.APIPrefix).Subrouter()
	api.Use(s.authMiddleware)

	// Health check
	s.router.HandleFunc("/health", s.healthCheck).Methods("GET")

	// Alerts endpoints
	api.HandleFunc("/alerts", s.listAlerts).Methods("GET")
	api.HandleFunc("/alerts/{id}", s.getAlert).Methods("GET")
	api.HandleFunc("/alerts/{id}/remediate", s.remediateAlert).Methods("POST")
	api.HandleFunc("/alerts/{id}/status", s.updateAlertStatus).Methods("PATCH")

	// Events endpoints
	api.HandleFunc("/events", s.listEvents).Methods("GET")
	api.HandleFunc("/events/{id}", s.getEvent).Methods("GET")

	// Ingestion endpoints
	api.HandleFunc("/ingest/now", s.triggerIngestion).Methods("POST")

	// User endpoints
	api.HandleFunc("/users/{id}/profile", s.getUserProfile).Methods("GET")
	api.HandleFunc("/users/{id}/history", s.getUserHistory).Methods("GET")

	// Rules endpoints
	api.HandleFunc("/rules", s.listRules).Methods("GET")
	api.HandleFunc("/rules/{id}", s.updateRule).Methods("PUT")
}

// Start starts the HTTP server
func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

// StartIngestion starts the background ingestion loop.
func (s *Server) StartIngestion(ctx context.Context) error {
	if s.ingestor == nil {
		return fmt.Errorf("ingestor is not configured")
	}
	return s.ingestor.Start(ctx)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := strings.TrimSpace(s.config.Security.JWTSecret)
		if secret == "" {
			next.ServeHTTP(w, r)
			return
		}

		const bearerPrefix = "Bearer "
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}

		token := strings.TrimSpace(strings.TrimPrefix(authHeader, bearerPrefix))
		if token == "" || token != secret {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Health check handler
func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// listAlerts lists alerts with optional filters
func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	userID := r.URL.Query().Get("user_id")

	limit := 50 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	offset := 0
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	ctx := r.Context()
	alerts, err := s.alertRepo.ListAlerts(ctx, limit, offset, severity, status, userID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list alerts: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

// getAlert retrieves a single alert by ID
func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid alert ID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	alert, err := s.alertRepo.GetAlert(ctx, id)
	if err != nil {
		if err.Error() == "alert not found" {
			http.Error(w, "Alert not found", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to get alert: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alert)
}

// RemediateRequest represents a remediation action request
type RemediateRequest struct {
	Action string `json:"action"` // "lock_user", "unlock_user", "revoke_key"
	Reason string `json:"reason"`
}

// remediateAlert performs remediation action on an alert
func (s *Server) remediateAlert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertIDStr := vars["id"]

	alertID, err := uuid.Parse(alertIDStr)
	if err != nil {
		http.Error(w, "Invalid alert ID", http.StatusBadRequest)
		return
	}

	// Get alert to determine remediation action
	ctx := r.Context()
	alert, err := s.alertRepo.GetAlert(ctx, alertID)
	if err != nil {
		if err.Error() == "alert not found" {
			http.Error(w, "Alert not found", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to get alert: %v", err), http.StatusInternalServerError)
		return
	}

	// Parse request body
	var req RemediateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Determine actor (for now, use a default system user)
	actor := "system"

	// Perform remediation based on alert type and action
	var remediationErr error
	switch req.Action {
	case "lock_user":
		if alert.UserID == "" {
			http.Error(w, "Alert has no user ID to lock", http.StatusBadRequest)
			return
		}
		remediationErr = s.remediationSvc.LockUserWithAlert(ctx, alertID, alert.UserID, actor, req.Reason)
	case "unlock_user":
		if alert.UserID == "" {
			http.Error(w, "Alert has no user ID to unlock", http.StatusBadRequest)
			return
		}
		remediationErr = s.remediationSvc.UnlockUserWithAlert(ctx, alertID, alert.UserID, actor, req.Reason)
	case "revoke_key":
		// Extract key ID from alert evidence
		keyID, ok := alert.Evidence["key_id"].(string)
		if !ok || keyID == "" {
			http.Error(w, "Alert has no key ID to revoke", http.StatusBadRequest)
			return
		}
		remediationErr = s.remediationSvc.RevokeAPIKeyWithAlert(ctx, alertID, keyID, actor, req.Reason)
	default:
		http.Error(w, fmt.Sprintf("Unknown action: %s", req.Action), http.StatusBadRequest)
		return
	}

	if remediationErr != nil {
		http.Error(w, fmt.Sprintf("Remediation failed: %v", remediationErr), http.StatusInternalServerError)
		return
	}

	// Update alert status to resolved
	if err := s.alertRepo.UpdateAlertStatus(ctx, alertID, models.AlertStatusResolved); err != nil {
		// Log but don't fail the request
		fmt.Printf("Failed to update alert status: %v\n", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Remediation action '%s' completed", req.Action),
	})
}

// remediationRepositoryAdapter adapts storage repositories to remediation.Repository interface
type remediationRepositoryAdapter struct {
	alertRepo       *storage.AlertRepository
	remediationRepo *storage.RemediationRepository
}

func (a *remediationRepositoryAdapter) LogRemediation(ctx context.Context, log *models.RemediationLog) error {
	return a.remediationRepo.LogRemediation(ctx, log)
}

func (a *remediationRepositoryAdapter) GetAlert(ctx context.Context, alertID string) (*models.Alert, error) {
	id, err := uuid.Parse(alertID)
	if err != nil {
		return nil, fmt.Errorf("invalid alert ID: %w", err)
	}
	return a.alertRepo.GetAlert(ctx, id)
}

// updateAlertStatus updates an alert's status
func (s *Server) updateAlertStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid alert ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	status := models.AlertStatus(req.Status)
	if status != models.AlertStatusOpen && status != models.AlertStatusInvestigating &&
		status != models.AlertStatusResolved && status != models.AlertStatusFalsePositive {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if err := s.alertRepo.UpdateAlertStatus(ctx, id, status); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update alert status: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
	})
}

// listEvents lists events with optional filters
func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	offset := 0
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	eventType := r.URL.Query().Get("event_type")
	actor := r.URL.Query().Get("actor")

	ctx := r.Context()
	events, err := s.eventRepo.ListEvents(ctx, limit, offset, eventType, actor)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list events: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"count":  len(events),
	})
}

// getEvent retrieves a single event by ID
func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid event ID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	event, err := s.eventRepo.GetEventByID(ctx, id)
	if err != nil {
		if err.Error() == "event not found" {
			http.Error(w, "Event not found", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to get event: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(event)
}

// triggerIngestion manually triggers event ingestion
func (s *Server) triggerIngestion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.ingestor.Ingest(ctx); err != nil {
		http.Error(w, fmt.Sprintf("Ingestion failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Ingestion triggered successfully",
	})
}

func (s *Server) getUserProfile(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) getUserHistory(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}
