package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// ---------------------------------------------------------------------------
// POST /api/validate
// ---------------------------------------------------------------------------

func handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeSignedError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var req struct {
		LicenseKey string `json:"license_key"`
		HWID       string `json:"hwid"`
		Nonce      string `json:"nonce"`
		TS         int64  `json:"ts"`
		Version    string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSignedError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	req.LicenseKey = normalizeLicenseKey(req.LicenseKey)
	req.HWID = normalizeHWID(req.HWID)
	req.Nonce = strings.TrimSpace(req.Nonce)

	replyErr := func(status int, msg string) {
		writeSignedErrorNonce(w, status, msg, req.Nonce, req.HWID)
	}

	if !checkNonce(req.Nonce) {
		replyErr(http.StatusBadRequest, "Invalid or reused nonce")
		return
	}

	now := time.Now().UTC()
	if req.TS == 0 || abs64(now.Unix()-req.TS) > 90 {
		replyErr(http.StatusBadRequest, "Stale request timestamp")
		return
	}

	clientIP := getClientIP(r)

	if req.LicenseKey == "" {
		replyErr(http.StatusOK, "License key required")
		return
	}
	if !validKeyPrefix(req.LicenseKey) {
		replyErr(http.StatusOK, "Invalid license key")
		return
	}
	if len(req.HWID) < minHWIDLen || len(req.HWID) > maxHWIDLen {
		replyErr(http.StatusOK, "Invalid HWID")
		return
	}
	if isRateLimited(clientIP) {
		replyErr(http.StatusTooManyRequests, "Rate limited")
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("[ERROR] begin tx: %v", err)
		replyErr(http.StatusInternalServerError, "Server error")
		return
	}
	defer func() { _ = tx.Rollback() }()

	var license struct {
		ID          int
		HWID        sql.NullString
		ExpiryDays  sql.NullInt64
		MaxDevices  int
		DevicesJSON sql.NullString
		Activated   bool
		ExpiryDate  sql.NullTime
		Lifetime    bool
		AllowedIPs  sql.NullString
	}

	err = tx.QueryRow(`
		SELECT id, hwid, expiry_days, max_devices, devices, activated, expiry_date, COALESCE(lifetime, false),
		       COALESCE(allowed_ips, '[]')
		FROM licenses WHERE lower(license_key) = lower($1)
		FOR UPDATE
	`, req.LicenseKey).Scan(
		&license.ID, &license.HWID, &license.ExpiryDays, &license.MaxDevices,
		&license.DevicesJSON, &license.Activated, &license.ExpiryDate, &license.Lifetime,
		&license.AllowedIPs,
	)

	if err == sql.ErrNoRows {
		_ = tx.Rollback()
		addLogAndDiscord(req.LicenseKey, "INVALID_KEY", clientIP, req.HWID, "Key not found")
		replyErr(http.StatusOK, "License not found or deleted")
		return
	}
	if err != nil {
		log.Printf("[ERROR] select license: %v", err)
		replyErr(http.StatusInternalServerError, "Server error")
		return
	}

	lifetime := isLifetimeKey(license.Lifetime, license.ExpiryDays)

	if !ipAllowed(parseAllowedIPs(license.AllowedIPs), clientIP) {
		_ = tx.Rollback()
		addLogAndDiscord(req.LicenseKey, "IP_REJECTED", clientIP, req.HWID,
			fmt.Sprintf("IP %s not bound to this key", clientIP))
		replyErr(http.StatusOK, "IP not authorized for this license")
		return
	}

	if isIPBlocked(clientIP) {
		_ = tx.Rollback()
		addLogAndDiscord(req.LicenseKey, "IP_BLOCKED_HIT", clientIP, req.HWID,
			"Blocked IP attempted validate")
		replyErr(http.StatusOK, "Access denied")
		return
	}
	if isHWIDBlocked(req.HWID) {
		_ = tx.Rollback()
		addLogAndDiscord(req.LicenseKey, "HWID_BLOCKED_HIT", clientIP, req.HWID,
			"Blocked HWID attempted validate")
		replyErr(http.StatusOK, "Access denied")
		return
	}

	if !lifetime && license.ExpiryDate.Valid && now.After(license.ExpiryDate.Time) {
		_ = tx.Rollback()
		addLogAndDiscord(req.LicenseKey, "EXPIRED", clientIP, req.HWID, "License expired")
		replyErr(http.StatusOK, "License expired")
		return
	}

	devices := parseDevicesJSON(license.DevicesJSON)

	if license.HWID.Valid {
		legacy := normalizeHWID(license.HWID.String)
		if legacy != "" && len(legacy) >= minHWIDLen && !deviceKnown(devices, legacy) {
			devices = append(devices, legacy)
		}
	}

	isKnownDevice := deviceKnown(devices, req.HWID)
	newDevice := false

	if !isKnownDevice {
		if license.MaxDevices > 0 && len(devices) >= license.MaxDevices {
			_ = tx.Rollback()
			addLogAndDiscord(req.LicenseKey, "MAX_DEVICES_REACHED", clientIP, req.HWID,
				fmt.Sprintf("Max devices reached (%d/%d)", len(devices), license.MaxDevices))
			writeEncryptedJSON(w, http.StatusOK, map[string]interface{}{
				"valid":        false,
				"error":        fmt.Sprintf("Max devices reached (%d/%d)", len(devices), license.MaxDevices),
				"max_devices":  license.MaxDevices,
				"devices_used": len(devices),
				"hwid":         req.HWID,
				"nonce":        req.Nonce,
				"ts":           now.Unix(),
			})
			return
		}
		devices = append(devices, req.HWID)
		newDevice = true
	}

	expiresAt := time.Time{}
	if license.ExpiryDate.Valid {
		expiresAt = license.ExpiryDate.Time.UTC()
	}

	primaryHWID := req.HWID
	if license.HWID.Valid && normalizeHWID(license.HWID.String) != "" {
		primaryHWID = normalizeHWID(license.HWID.String)
	}
	if len(devices) == 1 {
		primaryHWID = devices[0]
	}

	devicesJSON, err := json.Marshal(devices)
	if err != nil {
		replyErr(http.StatusInternalServerError, "Server error")
		return
	}

	activatedNow := false
	if !license.Activated {
		if lifetime {
			expiresAt = time.Time{}
			_, err = tx.Exec(`
				UPDATE licenses
				SET activated = true, activated_at = $1, expiry_date = NULL,
				    hwid = $2, devices = $3, last_check = $1
				WHERE id = $4
			`, now, primaryHWID, string(devicesJSON), license.ID)
		} else {
			expiresAt = now.AddDate(0, 0, int(license.ExpiryDays.Int64))
			_, err = tx.Exec(`
				UPDATE licenses
				SET activated = true, activated_at = $1, expiry_date = $2,
				    hwid = $3, devices = $4, last_check = $1
				WHERE id = $5
			`, now, expiresAt, primaryHWID, string(devicesJSON), license.ID)
		}
		if err != nil {
			log.Printf("[ERROR] activate license: %v", err)
			replyErr(http.StatusInternalServerError, "Server error")
			return
		}
		activatedNow = true
	} else {
		_, err = tx.Exec(`
			UPDATE licenses SET devices = $1, hwid = $2, last_check = $3 WHERE id = $4
		`, string(devicesJSON), primaryHWID, now, license.ID)
		if err != nil {
			log.Printf("[ERROR] update license devices: %v", err)
			replyErr(http.StatusInternalServerError, "Server error")
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[ERROR] commit: %v", err)
		replyErr(http.StatusInternalServerError, "Server error")
		return
	}

	if activatedNow {
		addLogAndDiscord(req.LicenseKey, "ACTIVATED", clientIP, req.HWID,
			fmt.Sprintf("First activation | Device: %s", req.HWID))
	} else if newDevice {
		addLogAndDiscord(req.LicenseKey, "NEW_DEVICE_ADDED", clientIP, req.HWID,
			fmt.Sprintf("New device added | Total: %d/%d", len(devices), license.MaxDevices))
	}

	touchLiveSession(req.LicenseKey, req.HWID, clientIP)

	tagBytes := make([]byte, 16)
	_, _ = rand.Read(tagBytes)
	serverTag := hex.EncodeToString(tagBytes)

	daysLeft := daysLeftFrom(expiresAt, now)

	resp := map[string]interface{}{
		"valid":         true,
		"nonce":         req.Nonce,
		"ts":            now.Unix(),
		"hwid":          req.HWID,
		"max_devices":   license.MaxDevices,
		"devices_used":  len(devices),
		"session_token": uuid.New().String(),
		"lifetime":      lifetime,
		"server_tag":    serverTag,
		"epic_creds":    epicClientCreds(),
	}
	if lifetime {
		resp["plan"] = "lifetime"
		resp["duration"] = "lifetime"
		resp["expiry_days"] = nil
	} else if !expiresAt.IsZero() {
		resp["expires_at"] = expiresAt.Format(time.RFC3339)
		if daysLeft >= 0 {
			resp["days_left"] = daysLeft
		}
		if license.ExpiryDays.Valid && license.ExpiryDays.Int64 > 0 {
			resp["expiry_days"] = license.ExpiryDays.Int64
		}
	}

	writeEncryptedJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// Version check — SHADE reads from `versions`.
// Nintendo reads from `nintendo_versions`.
// Two completely separate tables, two completely separate queries.
// ---------------------------------------------------------------------------

func lookupShadeVersion() string {
	var version string
	err := db.QueryRow(
		`SELECT version FROM versions WHERE is_active = TRUE ORDER BY id DESC LIMIT 1`,
	).Scan(&version)
	if err != nil || version == "" {
		return "1.0.0"
	}
	return version
}

func lookupNintendoVersion() string {
	var version string
	err := db.QueryRow(
		`SELECT version FROM nintendo_versions WHERE is_active = TRUE ORDER BY id DESC LIMIT 1`,
	).Scan(&version)
	if err != nil || version == "" {
		// Fallback so a fresh DB never hard-locks the Nintendo client.
		return lookupShadeVersion()
	}
	return version
}

func handleVersionCheckForTag(w http.ResponseWriter, r *http.Request, isNintendo bool) {
	clientVersion := strings.TrimSpace(r.URL.Query().Get("version"))
	nonce := strings.TrimSpace(r.URL.Query().Get("nonce"))

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Surrogate-Control", "no-store")
	w.Header().Set("Vary", "*")

	if nonce == "" || !checkNonce(nonce) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": "Invalid nonce",
			"nonce": nonce,
			"ts":    time.Now().Unix(),
		})
		return
	}

	var ts int64
	fmt.Sscanf(strings.TrimSpace(r.URL.Query().Get("ts")), "%d", &ts)
	if ts == 0 || abs64(time.Now().Unix()-ts) > 90 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": "Stale request",
			"nonce": nonce,
			"ts":    time.Now().Unix(),
		})
		return
	}

	requiredVersion := lookupShadeVersion()
	if isNintendo {
		requiredVersion = lookupNintendoVersion()
	}

	w.WriteHeader(http.StatusOK)

	if clientVersion == "" || clientVersion != requiredVersion {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":    false,
			"error":    "OUTDATED",
			"required": requiredVersion,
			"nonce":    nonce,
			"ts":       time.Now().Unix(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": true,
		"nonce": nonce,
		"ts":    time.Now().Unix(),
	})
}

func handleVersionCheck(w http.ResponseWriter, r *http.Request) {
	handleVersionCheckForTag(w, r, false)
}

func handleVersionCheckNintendo(w http.ResponseWriter, r *http.Request) {
	handleVersionCheckForTag(w, r, true)
}

func handleCurrentVersionForTag(w http.ResponseWriter, r *http.Request, isNintendo bool) {
	v := lookupShadeVersion()
	if isNintendo {
		v = lookupNintendoVersion()
	}
	writeEncryptedJSON(w, http.StatusOK, map[string]interface{}{"version": v})
}

func handleCurrentVersion(w http.ResponseWriter, r *http.Request) {
	handleCurrentVersionForTag(w, r, false)
}

func handleCurrentVersionNintendo(w http.ResponseWriter, r *http.Request) {
	handleCurrentVersionForTag(w, r, true)
}

// ---------------------------------------------------------------------------
// GET /healthz
// ---------------------------------------------------------------------------

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}