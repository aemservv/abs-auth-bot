package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

// ---------------------------------------------------------------------------
// POST /api/suspicious
//
// The Python client POSTs a JSON body describing a suspicious event.
// No signature — the endpoint is protected by the per-HWID rate limiter
// and by the fact that it isn't advertised anywhere public.
//
// Body schema (matches the Python reporter):
//
//	{
//	  "ts": "2026-01-14T12:34:56.789Z",
//	  "unix": 1768394096.789,
//	  "kind": "debugger",
//	  "detail": "IsDebuggerPresent returned TRUE",
//	  "extra": {...},
//	  "hwid": "…",
//	  "host": "DESKTOP-XYZ",
//	  "os": "Windows 10",
//	  "py": "3.11.5",
//	  "version": "1.2.3",
//	  "license": "NINTEN…AB12",
//	  "session_token": "abc123…"
//	}
// ---------------------------------------------------------------------------

type suspiciousReport struct {
	TS           string                 `json:"ts"`
	Unix         float64                `json:"unix"`
	Kind         string                 `json:"kind"`
	Detail       string                 `json:"detail"`
	Extra        map[string]interface{} `json:"extra"`
	HWID         string                 `json:"hwid"`
	Host         string                 `json:"host"`
	OS           string                 `json:"os"`
	Py           string                 `json:"py"`
	Version      string                 `json:"version"`
	License      string                 `json:"license"`
	SessionToken string                 `json:"session_token"`
}

func handleSuspicious(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"ok":false,"error":"method"}`, http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"ok":false,"error":"read"}`, http.StatusBadRequest)
		return
	}

	var rep suspiciousReport
	if err := json.Unmarshal(body, &rep); err != nil {
		http.Error(w, `{"ok":false,"error":"json"}`, http.StatusBadRequest)
		return
	}
	if rep.Kind == "" {
		http.Error(w, `{"ok":false,"error":"missing kind"}`, http.StatusBadRequest)
		return
	}

	// Truncate oversized fields so a hostile client can't fill the DB.
	trunc := func(s string, n int) string {
		if len(s) > n {
			return s[:n]
		}
		return s
	}
	rep.Kind = trunc(rep.Kind, 64)
	rep.Detail = trunc(rep.Detail, 1000)
	rep.HWID = trunc(rep.HWID, 255)
	rep.Host = trunc(rep.Host, 255)
	rep.OS = trunc(rep.OS, 128)
	rep.Py = trunc(rep.Py, 32)
	rep.Version = trunc(rep.Version, 32)
	rep.License = trunc(rep.License, 100)
	rep.SessionToken = trunc(rep.SessionToken, 64)

	// Rate limit per HWID — 10 reports/min per machine.
	if isSuspiciousRateLimited(rep.HWID) {
		http.Error(w, `{"ok":false,"error":"rate"}`, http.StatusTooManyRequests)
		return
	}

	clientIP := getClientIP(r)

	// Persist to `logs` so /logs and /stats can surface it too.
	if db != nil {
		_, _ = db.Exec(`
			INSERT INTO logs (license_key, action, ip_address, timestamp, hwid, details)
			VALUES ($1, $2, $3, $4, $5, $6)
		`,
			rep.License,
			"SUSPICIOUS_"+strings.ToUpper(rep.Kind),
			clientIP,
			time.Now(),
			rep.HWID,
			fmt.Sprintf("[%s] %s | %s %s | py %s",
				rep.Kind, rep.Detail, rep.OS, rep.Host, rep.Py),
		)
	}

	// Relay to Discord — best-effort, never blocks the response.
	go sendSuspiciousEmbed(rep, clientIP)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func isSuspiciousRateLimited(hwid string) bool {
	if hwid == "" {
		hwid = "unknown"
	}
	suspiciousRateMu.Lock()
	defer suspiciousRateMu.Unlock()

	now := time.Now()
	recent := suspiciousRateMap[hwid][:0]
	for _, t := range suspiciousRateMap[hwid] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	suspiciousRateMap[hwid] = recent

	if len(recent) >= 10 {
		return true
	}
	suspiciousRateMap[hwid] = append(suspiciousRateMap[hwid], now)
	return false
}

// sendSuspiciousEmbed posts a red embed to DISCORD_CHANNEL_SUSPICIOUS.
func sendSuspiciousEmbed(rep suspiciousReport, ip string) {
	if discordSession == nil {
		return
	}
	if DISCORD_CHANNEL_SUSPICIOUS == "" {
		return
	}

	color := 0xe74c3c // red — everything suspicious is red by default
	title := fmt.Sprintf("🚨 SUSPICIOUS: %s", strings.ToUpper(rep.Kind))

	// Some kinds are less alarming; keep them distinct but softer.
	softKinds := map[string]bool{
		"ticket_expired":  true,
		"stale_response":  true,
		"version_refused": true,
	}
	if softKinds[rep.Kind] {
		color = 0xe67e22
	}

	extraJSON := ""
	if len(rep.Extra) > 0 {
		if b, err := json.Marshal(rep.Extra); err == nil {
			extraJSON = string(b)
			if len(extraJSON) > 900 {
				extraJSON = extraJSON[:900] + "…"
			}
		}
	}

	fields := []*discordgo.MessageEmbedField{
		{Name: "🧩 Kind", Value: fmt.Sprintf("`%s`", rep.Kind), Inline: true},
		{Name: "🌐 IP", Value: fmt.Sprintf("`%s`", ip), Inline: true},
		{Name: "🖥️ Host", Value: fmt.Sprintf("`%s`", nonEmptyStr(rep.Host, "unknown")), Inline: true},
		{Name: "💻 OS", Value: fmt.Sprintf("`%s`", nonEmptyStr(rep.OS, "unknown")), Inline: true},
		{Name: "🐍 Python", Value: fmt.Sprintf("`%s`", nonEmptyStr(rep.Py, "unknown")), Inline: true},
		{Name: "🔢 Client", Value: fmt.Sprintf("`%s`", nonEmptyStr(rep.Version, "unknown")), Inline: true},
		{Name: "🔑 License", Value: fmt.Sprintf("`%s`", nonEmptyStr(rep.License, "n/a")), Inline: false},
		{Name: "🆔 HWID", Value: fmt.Sprintf("`%s`", nonEmptyStr(rep.HWID, "unknown")), Inline: false},
		{Name: "📝 Detail", Value: truncateStr(rep.Detail, 900), Inline: false},
	}
	if extraJSON != "" {
		fields = append(fields, &discordgo.MessageEmbedField{
			Name: "📦 Extra", Value: "```json\n" + extraJSON + "\n```", Inline: false,
		})
	}

	embed := &discordgo.MessageEmbed{
		Title:       title,
		Description: "A suspicious activity report was received from a client.",
		Color:       color,
		Fields:      fields,
		Timestamp:   time.Now().Format(time.RFC3339),
		Footer:      &discordgo.MessageEmbedFooter{Text: "ShadeFN Anti-Tamper"},
	}

	if _, err := discordSession.ChannelMessageSendEmbed(DISCORD_CHANNEL_SUSPICIOUS, embed); err != nil {
		log.Printf("[SUSPICIOUS] discord send failed: %v", err)
	}
}

func nonEmptyStr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}