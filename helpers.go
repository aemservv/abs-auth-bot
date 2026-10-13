package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

// ---------------------------------------------------------------------------
// Key / HWID normalization
// ---------------------------------------------------------------------------

func normalizeLicenseKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.Trim(key, "`\"'")
	key = strings.ReplaceAll(key, " ", "")
	return strings.ToUpper(key)
}

func normalizeHWID(hwid string) string {
	return strings.ToLower(strings.TrimSpace(hwid))
}

func isLifetimeKey(lifetime bool, expiryDays sql.NullInt64) bool {
	if lifetime {
		return true
	}
	if !expiryDays.Valid {
		return true
	}
	return expiryDays.Int64 <= 0
}

// ---------------------------------------------------------------------------
// Device list helpers
// ---------------------------------------------------------------------------

func parseDevicesJSON(raw sql.NullString) []string {
	if !raw.Valid || raw.String == "" || raw.String == "[]" {
		return nil
	}
	var devices []string
	if err := json.Unmarshal([]byte(raw.String), &devices); err != nil {
		return nil
	}
	return sanitizeDevices(devices)
}

func sanitizeDevices(devices []string) []string {
	seen := make(map[string]struct{}, len(devices))
	out := make([]string, 0, len(devices))
	for _, d := range devices {
		d = normalizeHWID(d)
		if d == "" || len(d) < minHWIDLen {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func deviceKnown(devices []string, hwid string) bool {
	for _, d := range devices {
		if d == hwid {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// IP binding helpers — exact IPs and CIDR ranges, e.g. ["1.2.3.4", "10.0.0.0/24"]
// ---------------------------------------------------------------------------

func parseAllowedIPs(raw sql.NullString) []string {
	if !raw.Valid || raw.String == "" || raw.String == "[]" {
		return nil
	}
	var ips []string
	if err := json.Unmarshal([]byte(raw.String), &ips); err != nil {
		return nil
	}
	seen := make(map[string]struct{}, len(ips))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(ip); err != nil {
			if net.ParseIP(ip) == nil {
				continue
			}
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func normIP(s string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func ipAllowed(allowed []string, ip string) bool {
	if len(allowed) == 0 {
		return true
	}
	parsed := normIP(ip)
	if parsed == nil {
		return false
	}
	for _, entry := range allowed {
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			if cidr.Contains(parsed) {
				return true
			}
			continue
		}
		if other := normIP(entry); other != nil && parsed.Equal(other) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Blocklists + live sessions — checked on EVERY validate, so a blocked IP or
// HWID is dead instantly even mid-run (client revalidates every 30 min).
// ---------------------------------------------------------------------------

func isIPBlocked(ip string) bool {
	if db == nil || ip == "" {
		return false
	}
	var one int
	err := db.QueryRow(`SELECT 1 FROM blocked_ips WHERE ip = $1`, strings.TrimSpace(ip)).Scan(&one)
	return err == nil
}

func isHWIDBlocked(hwid string) bool {
	if db == nil || hwid == "" {
		return false
	}
	var one int
	err := db.QueryRow(`SELECT 1 FROM blocked_hwids WHERE hwid = $1`, hwid).Scan(&one)
	return err == nil
}

type liveSession struct {
	License string
	HWID    string
	IP      string
	Seen    time.Time
}

var (
	liveMu       sync.Mutex
	liveSessions = make(map[string]liveSession)
)

func touchLiveSession(licenseKey, hwid, ip string) {
	liveMu.Lock()
	defer liveMu.Unlock()
	liveSessions[licenseKey] = liveSession{License: licenseKey, HWID: hwid, IP: ip, Seen: time.Now()}
	for k, v := range liveSessions {
		if time.Since(v.Seen) > 40*time.Minute {
			delete(liveSessions, k)
		}
	}
}

func listLiveSessions() []liveSession {
	liveMu.Lock()
	defer liveMu.Unlock()
	out := make([]liveSession, 0, len(liveSessions))
	for k, v := range liveSessions {
		if time.Since(v.Seen) > 40*time.Minute {
			delete(liveSessions, k)
			continue
		}
		out = append(out, v)
	}
	return out
}

func daysLeftFrom(expiry time.Time, now time.Time) int {
	if expiry.IsZero() {
		return -1
	}
	if !expiry.After(now) {
		return 0
	}
	days := int(expiry.Sub(now).Hours() / 24)
	if days < 1 {
		return 1
	}
	return days
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func isRateLimited(ip string) bool {
	rateMutex.Lock()
	defer rateMutex.Unlock()

	now := time.Now()

	// GC the map if it grows too large.
	if len(rateLimitMap) > 10000 {
		for k, times := range rateLimitMap {
			fresh := times[:0]
			for _, t := range times {
				if now.Sub(t) < time.Minute {
					fresh = append(fresh, t)
				}
			}
			if len(fresh) == 0 {
				delete(rateLimitMap, k)
			} else {
				rateLimitMap[k] = fresh
			}
		}
	}

	recent := rateLimitMap[ip][:0]
	for _, t := range rateLimitMap[ip] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(rateLimitMap, ip)
	} else {
		rateLimitMap[ip] = recent
	}

	if len(recent) >= rateLimitPerMin {
		return true
	}

	rateLimitMap[ip] = append(rateLimitMap[ip], now)
	return false
}

// ---------------------------------------------------------------------------
// Per-session Epic client credentials — issued ONLY inside a validated,
// signed response. The client binary carries none of these, so a cracker
// static-analyzing or patching the client finds no usable secrets and an
// offline (no live key) client cannot authenticate anywhere.
// Override via env; defaults are the long-lived public client pairs.
// ---------------------------------------------------------------------------

func epicClientCreds() map[string]string {
	return map[string]string{
		"sso":    envOr("EPIC_SSO_BASIC", "Y2ZhYTE0YzRiZjg3NDRlM2E1ZWY5YTVkNmMzNDU1OGQ6YmNiMGNkMzkyZmNkNGU1MGE3NmFkNDM4NGM2MjA1NDM="),
		"switch": envOr("EPIC_SWITCH_BASIC", "NTIyOWRjZDNhYzM4NDUyMDhiNDk2NjQ5MDkyZjI1MWI6ZTNiZDJkM2UtYmY4Yy00ODU3LTllN2QtZjNkOTQ3ZDIyMGM3"),
		"pc":     envOr("EPIC_PC_BASIC", "ZWM2ODRiOGM2ODdmNDc5ZmFkZWEzY2IyYWQ4M2Y1YzY6ZTFmMzFjMjExZjI4NDEzMTg2MjYyZDM3YTEzZmM4NGQ="),
	}
}

// ---------------------------------------------------------------------------
// Client IP — only trusts proxy headers when TRUST_PROXY=true
// ---------------------------------------------------------------------------

func getClientIP(r *http.Request) string {
	if os.Getenv("TRUST_PROXY") == "true" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
		if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
			return xrip
		}
	}
	ip := r.RemoteAddr
	if host, _, err := splitHostPort(ip); err == nil {
		return host
	}
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return strings.Trim(ip, "[]")
}

func splitHostPort(hostport string) (host, port string, err error) {
	if strings.HasPrefix(hostport, "[") {
		end := strings.Index(hostport, "]")
		if end < 0 {
			return "", "", fmt.Errorf("invalid address")
		}
		host = hostport[1:end]
		rest := hostport[end+1:]
		if strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return host, port, nil
	}
	colon := strings.LastIndex(hostport, ":")
	if colon < 0 {
		return hostport, "", nil
	}
	return hostport[:colon], hostport[colon+1:], nil
}

// ---------------------------------------------------------------------------
// Logging: DB insert + throttled Discord notification
// ---------------------------------------------------------------------------

var (
	discordLogMutex    sync.Mutex
	discordLogLimiter  = make(map[string]time.Time)
	discordActionCount = make(map[string]int)
	discordActionReset = time.Now()
)

func addLogAndDiscord(licenseKey, action, ip, hwid, details string) {
	if db != nil {
		if _, err := db.Exec(`
			INSERT INTO logs (license_key, action, ip_address, timestamp, hwid, details)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, licenseKey, action, ip, time.Now(), hwid, details); err != nil {
			log.Printf("[ERROR] Failed to add log: %v", err)
		}
	}

	discordLogMutex.Lock()

	// Reset per-action counters hourly.
	if time.Since(discordActionReset) > time.Hour {
		discordActionCount = make(map[string]int)
		discordActionReset = time.Now()
	}

	// Global cap: only 10 Discord alerts per action per hour.
	discordActionCount[action]++
	if discordActionCount[action] > 10 {
		discordLogMutex.Unlock()
		return
	}

	// Per-key+action 30s throttle.
	cacheKey := licenseKey + "_" + action
	if lastTime, ok := discordLogLimiter[cacheKey]; ok {
		if time.Since(lastTime) < 30*time.Second {
			discordLogMutex.Unlock()
			return
		}
	}
	discordLogLimiter[cacheKey] = time.Now()
	discordLogMutex.Unlock()

	sendDiscordLogByAction(licenseKey, action, ip, hwid, details)
}

// ---------------------------------------------------------------------------
// Discord embed notification
// ---------------------------------------------------------------------------

func sendDiscordLogByAction(licenseKey, action, ip, hwid, details string) {
	if discordSession == nil {
		return
	}

	fields := []*discordgo.MessageEmbedField{
		{Name: "📝 License Key", Value: fmt.Sprintf("`%s`", licenseKey), Inline: false},
		{Name: "🌐 IP Address", Value: fmt.Sprintf("`%s`", ip), Inline: true},
		{Name: "🖥️ HWID", Value: fmt.Sprintf("`%s`", hwid), Inline: true},
		{Name: "📋 Details", Value: details, Inline: false},
	}

	color := 0x95a5a6
	channelID := DISCORD_CHANNEL_CRACK

	switch action {
	case "VALIDATED", "ACTIVATED", "NEW_DEVICE_ADDED":
		color = 0x2ecc71
		channelID = DISCORD_CHANNEL_SUCCESS
	case "HWID_MISMATCH", "INVALID_KEY", "EXPIRED", "MAX_DEVICES_REACHED":
		color = 0xe74c3c
		channelID = DISCORD_CHANNEL_FAILED
	case "CREATED", "DELETED", "HWID_RESET", "EXTENDED", "VERSION_CHANGED", "UNBIND", "LOADER_UPLOADED":
		color = 0x9b59b6
		channelID = DISCORD_CHANNEL_CRACK
	}

	// Any SUSPICIOUS_* action goes to the dedicated suspicious channel.
	if strings.HasPrefix(action, "SUSPICIOUS_") {
		color = 0xe74c3c
		if DISCORD_CHANNEL_SUSPICIOUS != "" {
			channelID = DISCORD_CHANNEL_SUSPICIOUS
		}
	}

	embed := &discordgo.MessageEmbed{
		Title:       fmt.Sprintf("%s: %s", action, licenseKey),
		Description: details,
		Color:       color,
		Fields:      fields,
		Timestamp:   time.Now().Format(time.RFC3339),
		Footer:      &discordgo.MessageEmbedFooter{Text: "License System"},
	}

	if _, err := discordSession.ChannelMessageSendEmbed(channelID, embed); err != nil {
		log.Printf("[ERROR] Failed to send Discord log: %v", err)
	}
}