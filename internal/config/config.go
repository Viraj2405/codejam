package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds all application configuration
type Config struct {
	Server        ServerConfig
	Database      DatabaseConfig
	Redis         RedisConfig
	Scaleway      ScalewayConfig
	Ingestion     IngestionConfig
	Detection     DetectionConfig
	Security      SecurityConfig
	Notification  NotificationConfig
	Observability ObservabilityConfig
	GeoIP         GeoIPConfig
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host      string
	Port      string
	APIPrefix string
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	URL string
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	URL      string
	Password string
	DB       int
}

// ScalewayConfig holds Scaleway API configuration
type ScalewayConfig struct {
	APIKey         string
	ProjectID      string
	OrganizationID string
	APIURL         string
}

// IngestionConfig holds ingestion configuration
type IngestionConfig struct {
	PollIntervalSeconds int
	BatchSize           int
	MaxRetries          int
}

// DetectionConfig holds detection rules configuration
type DetectionConfig struct {
	FailedLoginWindowMin  int
	FailedLoginThreshold  int
	ImpossibleTravelSpeed float64
	AllowedIPRanges       []string
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	LockActionConfirm bool
	JWTSecret         string
	JWTExpiryHours    int
	BCryptCost        int
}

// NotificationConfig holds notification configuration
type NotificationConfig struct {
	SlackWebhookURL string
	SlackChannel    string
	EmailSMTPHost   string
	EmailSMTPPort   int
	EmailSMTPUser   string
	EmailSMTPPass   string
	EmailFrom       string
	EmailTo         string
}

// ObservabilityConfig holds observability configuration
type ObservabilityConfig struct {
	PrometheusEnabled bool
	PrometheusPort    int
	LogLevel          string
	LogFormat         string
}

// GeoIPConfig holds GeoIP configuration
type GeoIPConfig struct {
	Enabled bool
	DBPath  string
	APIURL  string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	// Load .env file if it exists (ignore error if not found)
	_ = godotenv.Load()

	cfg := &Config{
		Server: ServerConfig{
			Host:      getEnv("SERVER_HOST", "0.0.0.0"),
			Port:      getEnv("SERVER_PORT", "8081"),
			APIPrefix: getEnv("API_PREFIX", "/api/v1"),
		},
		Database: DatabaseConfig{
			URL: getEnv("DB_URL", "postgres://auditsentinel:changeme@localhost:5432/auditsentinel?sslmode=disable"),
		},
		Redis: RedisConfig{
			URL:      getEnv("REDIS_URL", "redis://localhost:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
		},
		Scaleway: ScalewayConfig{
			APIKey:         getEnv("SCALEWAY_API_KEY", ""),
			ProjectID:      getEnv("SCALEWAY_PROJECT_ID", ""),
			OrganizationID: getEnv("SCALEWAY_ORG_ID", ""),
			APIURL:         getEnv("SCALEWAY_API_URL", "https://api.scaleway.com"),
		},
		Ingestion: IngestionConfig{
			PollIntervalSeconds: getEnvAsInt("POLL_INTERVAL_SECONDS", 300),
			BatchSize:           getEnvAsInt("INGEST_BATCH_SIZE", 100),
			MaxRetries:          getEnvAsInt("INGEST_MAX_RETRIES", 3),
		},
		Detection: DetectionConfig{
			FailedLoginWindowMin:  getEnvAsInt("FAILED_LOGIN_WINDOW_MIN", 15),
			FailedLoginThreshold:  getEnvAsInt("FAILED_LOGIN_THRESHOLD", 5),
			ImpossibleTravelSpeed: getEnvAsFloat("IMPOSSIBLE_TRAVEL_SPEED_KMH", 1000),
			AllowedIPRanges:       getEnvAsSlice("ALLOWED_IP_RANGES", []string{}),
		},
		Security: SecurityConfig{
			LockActionConfirm: getEnvAsBool("LOCK_ACTION_CONFIRM", true),
			JWTSecret:         getEnv("JWT_SECRET", ""),
			JWTExpiryHours:    getEnvAsInt("JWT_EXPIRY_HOURS", 24),
			BCryptCost:        getEnvAsInt("BCRYPT_COST", 10),
		},
		Notification: NotificationConfig{
			SlackWebhookURL: getEnv("SLACK_WEBHOOK_URL", ""),
			SlackChannel:    getEnv("SLACK_CHANNEL", "#security-alerts"),
			EmailSMTPHost:   getEnv("EMAIL_SMTP_HOST", ""),
			EmailSMTPPort:   getEnvAsInt("EMAIL_SMTP_PORT", 587),
			EmailSMTPUser:   getEnv("EMAIL_SMTP_USER", ""),
			EmailSMTPPass:   getEnv("EMAIL_SMTP_PASSWORD", ""),
			EmailFrom:       getEnv("EMAIL_FROM", ""),
			EmailTo:         getEnv("EMAIL_TO", ""),
		},
		Observability: ObservabilityConfig{
			PrometheusEnabled: getEnvAsBool("PROMETHEUS_ENABLED", true),
			PrometheusPort:    getEnvAsInt("PROMETHEUS_PORT", 9090),
			LogLevel:          getEnv("LOG_LEVEL", "info"),
			LogFormat:         getEnv("LOG_FORMAT", "json"),
		},
		GeoIP: GeoIPConfig{
			Enabled: getEnvAsBool("GEOIP_ENABLED", true),
			DBPath:  getEnv("GEOIP_DB_PATH", "./data/GeoLite2-City.mmdb"),
			APIURL:  getEnv("GEOIP_API_URL", "https://ipapi.co"),
		},
	}

	if cfg.Database.URL == "" {
		return nil, fmt.Errorf("DB_URL is required")
	}

	return cfg, nil
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvAsFloat(key string, defaultValue float64) float64 {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvAsSlice(key string, defaultValue []string) []string {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	// Simple comma-separated split
	result := []string{}
	for _, item := range splitString(valueStr, ",") {
		if trimmed := trimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return defaultValue
	}
	return result
}

func splitString(s, sep string) []string {
	result := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
