package main

import (
	"fmt"
	"strings"

	"safe-road/internal/auth"
	"safe-road/internal/config"
	"safe-road/internal/logjson"
)

const (
	generatedSessionSecretBytes = 32
	generatedAdminPasswordBytes = 16
	generatedAdminAPIKeyBytes   = 24
	minAdminPasswordLength      = 12
	minAdminAPIKeyLength        = 24
)

type runtimeSecurity struct {
	sessionSecret []byte
	adminPassword string
	adminAPIKey   string
}

func loadRuntimeSecurity() (runtimeSecurity, error) {
	sessionSeed, err := auth.GenerateSecureRandomString(generatedSessionSecretBytes)
	if err != nil {
		return runtimeSecurity{}, fmt.Errorf("generate session secret: %w", err)
	}

	adminPassword, err := config.SecretStringE("SAFE_ROAD_ADMIN_PASSWORD")
	if err != nil {
		return runtimeSecurity{}, err
	}
	adminAPIKey, err := config.SecretStringE("SAFE_ROAD_ADMIN_API_KEY")
	if err != nil {
		return runtimeSecurity{}, err
	}

	if config.IsProduction() {
		if err := validateProductionAdminPassword(adminPassword); err != nil {
			return runtimeSecurity{}, err
		}
		if err := validateProductionAdminAPIKey(adminAPIKey); err != nil {
			return runtimeSecurity{}, err
		}
		return runtimeSecurity{
			sessionSecret: []byte(sessionSeed),
			adminPassword: adminPassword,
			adminAPIKey:   adminAPIKey,
		}, nil
	}

	if adminPassword == "" {
		adminPassword, err = auth.GenerateSecureRandomString(generatedAdminPasswordBytes)
		if err != nil {
			return runtimeSecurity{}, fmt.Errorf("generate admin password: %w", err)
		}
		logjson.Warn("generated temporary local-only admin password", map[string]any{
			"service":        "core-api",
			"config_key":     "SAFE_ROAD_ADMIN_PASSWORD",
			"generated_only": true,
		})
		logjson.Info("generated local admin password", map[string]any{
			"service": "core-api",
			"value":   adminPassword,
		})
	} else if err := validateProductionAdminPassword(adminPassword); err != nil {
		logjson.Warn("admin password validation warning", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
	}

	if adminAPIKey == "" {
		adminAPIKey, err = auth.GenerateSecureRandomString(generatedAdminAPIKeyBytes)
		if err != nil {
			return runtimeSecurity{}, fmt.Errorf("generate admin API key: %w", err)
		}
		logjson.Warn("generated temporary local-only admin api key", map[string]any{
			"service":        "core-api",
			"config_key":     "SAFE_ROAD_ADMIN_API_KEY",
			"generated_only": true,
		})
		logjson.Info("generated local admin api key", map[string]any{
			"service": "core-api",
			"value":   adminAPIKey,
		})
	} else if err := validateProductionAdminAPIKey(adminAPIKey); err != nil {
		logjson.Warn("admin api key validation warning", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
	}

	return runtimeSecurity{
		sessionSecret: []byte(sessionSeed),
		adminPassword: adminPassword,
		adminAPIKey:   adminAPIKey,
	}, nil
}

func validateProductionAdminPassword(password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return fmt.Errorf("SAFE_ROAD_ADMIN_PASSWORD or SAFE_ROAD_ADMIN_PASSWORD_FILE is required when SAFE_ROAD_ENV=%s", config.Environment())
	}
	if len(password) < minAdminPasswordLength {
		return fmt.Errorf("SAFE_ROAD_ADMIN_PASSWORD is too weak: need at least %d characters", minAdminPasswordLength)
	}
	if looksPlaceholderSecret(password) {
		return fmt.Errorf("SAFE_ROAD_ADMIN_PASSWORD uses a placeholder-style value; replace it with a real secret")
	}
	return nil
}

func validateProductionAdminAPIKey(apiKey string) error {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return fmt.Errorf("SAFE_ROAD_ADMIN_API_KEY or SAFE_ROAD_ADMIN_API_KEY_FILE is required when SAFE_ROAD_ENV=%s", config.Environment())
	}
	if len(apiKey) < minAdminAPIKeyLength {
		return fmt.Errorf("SAFE_ROAD_ADMIN_API_KEY is too short: need at least %d characters", minAdminAPIKeyLength)
	}
	if looksPlaceholderSecret(apiKey) {
		return fmt.Errorf("SAFE_ROAD_ADMIN_API_KEY uses a placeholder-style value; replace it with a real secret")
	}
	return nil
}

func looksPlaceholderSecret(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("-", "", "_", "", " ", "")
	normalized = replacer.Replace(normalized)

	if normalized == "" {
		return true
	}

	exactPlaceholders := []string{
		"password",
		"adminpassword",
		"apikey",
		"token",
		"secret",
		"testkey",
		"testpass",
		"example",
		"sample",
		"placeholder",
	}

	for _, marker := range exactPlaceholders {
		if normalized == marker {
			return true
		}
	}

	patternPlaceholders := []string{
		"changeme",
		"replacewith",
		"your",
	}

	for _, marker := range patternPlaceholders {
		if strings.HasPrefix(normalized, marker) || strings.Contains(normalized, marker) {
			return true
		}
	}

	return false
}
