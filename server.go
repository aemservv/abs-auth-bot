package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	_ "github.com/lib/pq"
)

// Loader path is hardcoded — not sensitive, lives next to the binary.
const LoaderFilePath = "./loader.exe"

// All key prefixes the server issues or accepts.
var KEY_PREFIXES = []string{"NINTENDO-", "SHADE-"}

// validKeyPrefix returns true if the key starts with any accepted prefix.
func validKeyPrefix(key string) bool {
	for _, p := range KEY_PREFIXES {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

var (
	// REQUIRED
	DATABASE_URL               = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	DISCORD_BOT_TOKEN          = strings.TrimSpace(os.Getenv("DISCORD_BOT_TOKEN"))
	DISCORD_CUSTOMER_BOT_TOKEN = strings.TrimSpace(os.Getenv("DISCORD_CUSTOMER_BOT_TOKEN"))

	// Signing keys (see signing.go)
	AUTH_SIGNING_PRIVKEY_B64 = strings.TrimSpace(os.Getenv("AUTH_SIGNING_PRIVKEY_B64"))
	AUTH_SIGNING_PUBKEY_B64  = strings.TrimSpace(os.Getenv("AUTH_SIGNING_PUBKEY_B64"))

	// Admin bot / log channels
	DISCORD_ADMIN_ID        = envOr("DISCORD_ADMIN_ID", "1305950442089484319")
	DISCORD_GUILD_ID        = envOr("DISCORD_GUILD_ID", "1378703394260389950")
	DISCORD_CHANNEL_SUCCESS = envOr("DISCORD_CHANNEL_SUCCESS", "1523764616415678474")
	DISCORD_CHANNEL_FAILED  = envOr("DISCORD_CHANNEL_FAILED", "1523764701270511646")
	DISCORD_CHANNEL_CRACK   = envOr("DISCORD_CHANNEL_CRACK", "1378703394662777026")
	DISCORD_CHANNEL_SUSPICIOUS = envOr("DISCORD_CHANNEL_SUSPICIOUS", "1558470775281815673")

	// Customer bot
	DISCORD_CUSTOMER_GUILD_ID = envOr("DISCORD_CUSTOMER_GUILD_ID", "1504541789141598452")
	DISCORD_CUSTOMER_ROLE_ID  = envOr("DISCORD_CUSTOMER_ROLE_ID", "1504542165307490334")
	DISCORD_CUSTOMER_CHANNELS = envOr("DISCORD_CUSTOMER_CHANNELS", "1533137448216035378,1553801587946819645")
)

const (
	minHWIDLen      = 32
	maxHWIDLen      = 128
	maxBodyBytes    = 1 << 20
	rateLimitPerMin = 20
)

var (
	db             *sql.DB
	discordSession *discordgo.Session
	rateLimitMap   = make(map[string][]time.Time)
	rateMutex      sync.Mutex

	// Suspicious-report throttle (per HWID).
	suspiciousRateMap = make(map[string][]time.Time)
	suspiciousRateMu  sync.Mutex
)

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func customerChannelAllowed(channelID string) bool {
	for _, id := range strings.Split(DISCORD_CUSTOMER_CHANNELS, ",") {
		if strings.TrimSpace(id) == channelID {
			return true
		}
	}
	return false
}

func main() {
	if DATABASE_URL == "" {
		log.Fatal("❌ DATABASE_URL environment variable is required")
	}
	if DISCORD_BOT_TOKEN == "" {
		log.Println("⚠️ DISCORD_BOT_TOKEN is empty — admin bot will be disabled")
	}
	if DISCORD_CUSTOMER_BOT_TOKEN == "" {
		log.Println("⚠️ DISCORD_CUSTOMER_BOT_TOKEN is empty — customer bot will be disabled")
	}

	if err := initCrypto(); err != nil {
		log.Fatalf("crypto init: %v", err)
	}
	if err := initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	go initDiscordBot()
	go initCustomerBot()

	// Auth API
	http.HandleFunc("/api/validate", handleValidate)
	http.HandleFunc("/api/version/check", handleVersionCheck)
	http.HandleFunc("/api/version/check/nintendo", handleVersionCheckNintendo)
	http.HandleFunc("/api/version/current", handleCurrentVersion)
	http.HandleFunc("/api/version/current/nintendo", handleCurrentVersionNintendo)

	// Suspicious-activity reporting (client → server → Discord).
	http.HandleFunc("/api/suspicious", handleSuspicious)

	// Exposes the current signing pubkey — safe to be public.
	http.HandleFunc("/api/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(pubkeyB64()))
	})

	// Health
	http.HandleFunc("/healthz", handleHealthz)

	// Landing
	http.HandleFunc("/", serveIndex)

	port := envOr("PORT", "8080")
	log.Println("License Server running on port:", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func initDB() error {
	log.Println("Connecting to PostgreSQL...")

	var err error
	db, err = sql.Open("postgres", DATABASE_URL)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Minute * 3)

	if err = db.Ping(); err != nil {
		return fmt.Errorf("ping failed: %v", err)
	}
	log.Println("Connected to PostgreSQL!")

	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS licenses (
			id SERIAL PRIMARY KEY,
			license_key VARCHAR(100) UNIQUE NOT NULL,
			expiry_days INT DEFAULT 30,
			note TEXT,
			activated BOOLEAN DEFAULT FALSE,
			activated_at TIMESTAMP,
			last_check TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			hwid VARCHAR(255) DEFAULT '',
			max_devices INT DEFAULT 1,
			devices TEXT DEFAULT '[]',
			resets INT DEFAULT 0,
			expiry_date TIMESTAMP,
			lifetime BOOLEAN NOT NULL DEFAULT FALSE,
			discord_id VARCHAR(32) DEFAULT '',
			redeemed_at TIMESTAMP
		)
	`); err != nil {
		return err
	}

	// IP binding: empty list = any IP allowed. Managed via /bindip /unbindip.
	if _, err = db.Exec(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS allowed_ips TEXT DEFAULT '[]'`); err != nil {
		return err
	}

	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS blocked_ips (
			ip VARCHAR(64) PRIMARY KEY,
			reason TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return err
	}
	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS blocked_hwids (
			hwid VARCHAR(255) PRIMARY KEY,
			reason TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return err
	}

	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS logs (
			id SERIAL PRIMARY KEY,
			license_key VARCHAR(100),
			action VARCHAR(50),
			ip_address VARCHAR(50),
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			hwid VARCHAR(255),
			details TEXT
		)
	`); err != nil {
		return err
	}

	// SHADE version — untouched, same as before.
	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS versions (
			id SERIAL PRIMARY KEY,
			version VARCHAR(20) NOT NULL,
			is_active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return err
	}

	// Nintendo version — brand new, dedicated table. Same shape as `versions`
	// so the code paths are symmetric, but entirely separate rows.
	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS nintendo_versions (
			id SERIAL PRIMARY KEY,
			version VARCHAR(20) NOT NULL,
			is_active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return err
	}

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM versions`).Scan(&count)
	if count == 0 {
		db.Exec(`INSERT INTO versions (version, is_active) VALUES ('1.2.2', TRUE)`)
	}

	var nCount int
	db.QueryRow(`SELECT COUNT(*) FROM nintendo_versions`).Scan(&nCount)
	if nCount == 0 {
		db.Exec(`INSERT INTO nintendo_versions (version, is_active) VALUES ('1.2.3', TRUE)`)
	}

	// Idempotent column adds for older DBs
	_, _ = db.Exec(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS lifetime BOOLEAN NOT NULL DEFAULT FALSE`)
	_, _ = db.Exec(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS discord_id VARCHAR(32) DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS redeemed_at TIMESTAMP`)

	// Backfill
	_, _ = db.Exec(`UPDATE licenses SET lifetime = TRUE WHERE COALESCE(lifetime, false) = false AND expiry_days IS NULL`)
	_, _ = db.Exec(`UPDATE licenses SET expiry_days = NULL, expiry_date = NULL WHERE lifetime = TRUE`)

	log.Println("Database tables ready!")
	return nil
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "index.html")
}