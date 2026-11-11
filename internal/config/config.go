package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

const defaultConfigPath = "config/config.yaml"

type Config struct {
	Environment     string                `yaml:"env" env:"ENVIRONMENT" env-default:"development"`
	Server          ServerConfig          `yaml:"server"`
	Database        DatabaseConfig        `yaml:"database"`
	Tokens          TokensConfig          `yaml:"tokens"`
	Sessions        SessionsConfig        `yaml:"sessions"`
	Password        PasswordConfig        `yaml:"password"`
	LoginProtection LoginProtectionConfig `yaml:"login_protection"`
}

type ServerConfig struct {
	Host            string        `env:"SERVER_HOST" env-default:"0.0.0.0"`
	Port            string        `env:"SERVER_PORT" env-default:"8090"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env-default:"10s"`
	// Брать IP клиента из X-Forwarded-For. Включать, только если сервис стоит за своим
	// прокси: иначе клиент подделает заголовок и обойдет лимит запросов по IP.
	TrustProxy bool `env:"TRUST_PROXY" env-default:"false"`
}

type DatabaseConfig struct {
	URL            string        `env:"DATABASE_URL" env-required:"true"`
	MaxConns       int32         `yaml:"max_conns" env-default:"20"`
	ConnectTimeout time.Duration `yaml:"connect_timeout" env-default:"10s"`
}

type TokensConfig struct {
	PrivateKeyPath    string        `env:"JWT_PRIVATE_KEY_PATH" env-default:"keys/jwt_private.pem"`
	Issuer            string        `yaml:"issuer" env:"JWT_ISSUER" env-default:"auth-service"`
	AccessTTL         time.Duration `yaml:"access_ttl" env-default:"15m"`
	RefreshTTL        time.Duration `yaml:"refresh_ttl" env-default:"720h"`
	RefreshReuseGrace time.Duration `yaml:"refresh_reuse_grace" env-default:"10s"`
}

type SessionsConfig struct {
	MaxPerUser      int           `yaml:"max_per_user" env-default:"10"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" env-default:"1h"`
}

type PasswordConfig struct {
	MemoryKiB   uint32 `yaml:"memory_kib" env-default:"19456"`
	Iterations  uint32 `yaml:"iterations" env-default:"2"`
	Parallelism uint8  `yaml:"parallelism" env-default:"1"`
	MinLength   int    `yaml:"min_length" env-default:"8"`
}

type LoginProtectionConfig struct {
	MaxFailedAttempts int           `yaml:"max_failed_attempts" env-default:"5"`
	Lockout           time.Duration `yaml:"lockout" env-default:"5m"`
	IPRatePerMinute   int           `yaml:"ip_rate_per_minute" env-default:"30"`
	IPBurst           int           `yaml:"ip_burst" env-default:"10"`
}

// Load читает .env (если есть), затем YAML-конфиг и переменные окружения.
// Переменные окружения имеют приоритет над YAML.
// Путь к YAML берется из CONFIG_PATH, по умолчанию config/config.yaml.
func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("load .env file: %w", err)
	}

	path := os.Getenv("CONFIG_PATH")
	explicit := path != ""
	if !explicit {
		path = defaultConfigPath
	}

	var cfg Config
	_, statErr := os.Stat(path)
	switch {
	case statErr == nil:
		if err := cleanenv.ReadConfig(path, &cfg); err != nil {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
	case explicit:
		return nil, fmt.Errorf("config file %s: %w", path, statErr)
	default:
		if err := cleanenv.ReadEnv(&cfg); err != nil {
			return nil, fmt.Errorf("read environment: %w", err)
		}
	}

	return &cfg, nil
}
