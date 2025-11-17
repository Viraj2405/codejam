package remediation

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/scaleway/audit-sentinel/internal/config"
	"github.com/scaleway/audit-sentinel/internal/models"
	"github.com/scaleway/audit-sentinel/pkg/scaleway"
)

// Service handles remediation actions
type Service struct {
	config     *config.Config
	client     *scaleway.Client
	repository RemediationRepository
}

// RemediationRepository defines the interface for remediation storage
type RemediationRepository interface {
	LogRemediation(ctx context.Context, log *models.RemediationLog) error
	GetAlert(ctx context.Context, alertID string) (*models.Alert, error)
}

// NewService creates a new remediation service
func NewService(cfg *config.Config, client *scaleway.Client, repo RemediationRepository) *Service {
	return &Service{
		config:     cfg,
		client:     client,
		repository: repo,
	}
}

// LockUser locks a user account via Scaleway IAM
func (s *Service) LockUser(ctx context.Context, userID string, actor string, reason string) error {
	// Call Scaleway IAM API to lock user
	if err := s.client.LockUser(ctx, userID); err != nil {
		// Log failed remediation attempt
		log := &models.RemediationLog{
			ActorUser:  actor,
			ActionType: models.ActionTypeLockUser,
			Payload: map[string]any{
				"user_id": userID,
				"reason":  reason,
			},
			Result: fmt.Sprintf("failed: %v", err),
		}
		_ = s.repository.LogRemediation(ctx, log)
		return fmt.Errorf("failed to lock user: %w", err)
	}

	// Log remediation action
	log := &models.RemediationLog{
		ActorUser:  actor,
		ActionType: models.ActionTypeLockUser,
		Payload: map[string]any{
			"user_id": userID,
			"reason":  reason,
		},
		Result: "success",
	}

	return s.repository.LogRemediation(ctx, log)
}

// UnlockUser unlocks a user account via Scaleway IAM
func (s *Service) UnlockUser(ctx context.Context, userID string, actor string, reason string) error {
	// Call Scaleway IAM API to unlock user
	if err := s.client.UnlockUser(ctx, userID); err != nil {
		// Log failed remediation attempt
		log := &models.RemediationLog{
			ActorUser:  actor,
			ActionType: models.ActionTypeUnlockUser,
			Payload: map[string]any{
				"user_id": userID,
				"reason":  reason,
			},
			Result: fmt.Sprintf("failed: %v", err),
		}
		_ = s.repository.LogRemediation(ctx, log)
		return fmt.Errorf("failed to unlock user: %w", err)
	}

	// Log remediation action
	log := &models.RemediationLog{
		ActorUser:  actor,
		ActionType: models.ActionTypeUnlockUser,
		Payload: map[string]any{
			"user_id": userID,
			"reason":  reason,
		},
		Result: "success",
	}

	return s.repository.LogRemediation(ctx, log)
}

// RevokeAPIKey revokes an API key via Scaleway IAM
func (s *Service) RevokeAPIKey(ctx context.Context, keyID string, actor string, reason string) error {
	// Call Scaleway IAM API to revoke key
	if err := s.client.RevokeAPIKey(ctx, keyID); err != nil {
		// Log failed remediation attempt
		log := &models.RemediationLog{
			ActorUser:  actor,
			ActionType: models.ActionTypeRevokeKey,
			Payload: map[string]any{
				"key_id": keyID,
				"reason": reason,
			},
			Result: fmt.Sprintf("failed: %v", err),
		}
		_ = s.repository.LogRemediation(ctx, log)
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	// Log remediation action
	log := &models.RemediationLog{
		ActorUser:  actor,
		ActionType: models.ActionTypeRevokeKey,
		Payload: map[string]any{
			"key_id": keyID,
			"reason": reason,
		},
		Result: "success",
	}

	return s.repository.LogRemediation(ctx, log)
}

// LockUserWithAlert locks a user account and associates the action with an alert
func (s *Service) LockUserWithAlert(ctx context.Context, alertID uuid.UUID, userID string, actor string, reason string) error {
	// Call Scaleway IAM API to lock user
	if err := s.client.LockUser(ctx, userID); err != nil {
		// Log failed remediation attempt
		log := &models.RemediationLog{
			ID:         uuid.New(),
			AlertID:    alertID,
			ActorUser:  actor,
			ActionType: models.ActionTypeLockUser,
			Payload: map[string]any{
				"user_id": userID,
				"reason":  reason,
			},
			Result: fmt.Sprintf("failed: %v", err),
		}
		_ = s.repository.LogRemediation(ctx, log)
		return fmt.Errorf("failed to lock user: %w", err)
	}

	// Log remediation action
	log := &models.RemediationLog{
		ID:         uuid.New(),
		AlertID:    alertID,
		ActorUser:  actor,
		ActionType: models.ActionTypeLockUser,
		Payload: map[string]any{
			"user_id": userID,
			"reason":  reason,
		},
		Result: "success",
	}

	return s.repository.LogRemediation(ctx, log)
}

// UnlockUserWithAlert unlocks a user account and associates the action with an alert
func (s *Service) UnlockUserWithAlert(ctx context.Context, alertID uuid.UUID, userID string, actor string, reason string) error {
	// Call Scaleway IAM API to unlock user
	if err := s.client.UnlockUser(ctx, userID); err != nil {
		// Log failed remediation attempt
		log := &models.RemediationLog{
			ID:         uuid.New(),
			AlertID:    alertID,
			ActorUser:  actor,
			ActionType: models.ActionTypeUnlockUser,
			Payload: map[string]any{
				"user_id": userID,
				"reason":  reason,
			},
			Result: fmt.Sprintf("failed: %v", err),
		}
		_ = s.repository.LogRemediation(ctx, log)
		return fmt.Errorf("failed to unlock user: %w", err)
	}

	// Log remediation action
	log := &models.RemediationLog{
		ID:         uuid.New(),
		AlertID:    alertID,
		ActorUser:  actor,
		ActionType: models.ActionTypeUnlockUser,
		Payload: map[string]any{
			"user_id": userID,
			"reason":  reason,
		},
		Result: "success",
	}

	return s.repository.LogRemediation(ctx, log)
}

// RevokeAPIKeyWithAlert revokes an API key and associates the action with an alert
func (s *Service) RevokeAPIKeyWithAlert(ctx context.Context, alertID uuid.UUID, keyID string, actor string, reason string) error {
	// Call Scaleway IAM API to revoke key
	if err := s.client.RevokeAPIKey(ctx, keyID); err != nil {
		// Log failed remediation attempt
		log := &models.RemediationLog{
			ID:         uuid.New(),
			AlertID:    alertID,
			ActorUser:  actor,
			ActionType: models.ActionTypeRevokeKey,
			Payload: map[string]any{
				"key_id": keyID,
				"reason": reason,
			},
			Result: fmt.Sprintf("failed: %v", err),
		}
		_ = s.repository.LogRemediation(ctx, log)
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	// Log remediation action
	log := &models.RemediationLog{
		ID:         uuid.New(),
		AlertID:    alertID,
		ActorUser:  actor,
		ActionType: models.ActionTypeRevokeKey,
		Payload: map[string]any{
			"key_id": keyID,
			"reason": reason,
		},
		Result: "success",
	}

	return s.repository.LogRemediation(ctx, log)
}
