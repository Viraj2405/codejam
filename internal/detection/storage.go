package detection

import (
	"context"
	"database/sql"

	"github.com/scaleway/audit-sentinel/internal/models"
	"github.com/scaleway/audit-sentinel/internal/storage"
)

// DetectionStorageImpl implements DetectionStorage interface
type DetectionStorageImpl struct {
	db        *sql.DB
	alertRepo *storage.AlertRepository
}

// NewDetectionStorage creates a new detection storage implementation
func NewDetectionStorage(db *sql.DB) *DetectionStorageImpl {
	return &DetectionStorageImpl{
		db:        db,
		alertRepo: storage.NewAlertRepository(db),
	}
}

// StoreAlert stores an alert in the database
func (s *DetectionStorageImpl) StoreAlert(ctx context.Context, alert *models.Alert) error {
	return s.alertRepo.StoreAlert(ctx, alert)
}

// GetUserProfile gets a user profile (not needed for MVP, but required by interface)
func (s *DetectionStorageImpl) GetUserProfile(ctx context.Context, userID string) (*models.UserProfile, error) {
	// MVP: Not implemented, return nil
	return nil, nil
}

// UpdateUserProfile updates a user profile (not needed for MVP, but required by interface)
func (s *DetectionStorageImpl) UpdateUserProfile(ctx context.Context, profile *models.UserProfile) error {
	// MVP: Not implemented, return nil
	return nil
}
