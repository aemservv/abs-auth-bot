package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

func initDiscordBot() {
	token := DISCORD_BOT_TOKEN
	if token == "" {
		log.Println("⚠️ DISCORD_BOT_TOKEN is empty. Admin Discord bot disabled.")
		return
	}

	var err error
	discordSession, err = discordgo.New("Bot " + token)
	if err != nil {
		log.Printf("⚠️ Discord bot failed to start: %v", err)
		return
	}

	discordSession.Identify.Intents = discordgo.IntentsGuildMessages

	discordSession.AddHandler(func(s *discordgo.Session, i *discordgo.InteractionCreate) {
		if i.Type == discordgo.InteractionApplicationCommand {
			handleSlashCommand(s, i)
			}
	})

	if err = discordSession.Open(); err != nil {
		log.Printf("⚠️ Discord bot failed to connect: %v", err)
		return
	}

	registerSlashCommands()
	log.Println("Discord admin bot is running!")
}

// ---------------------------------------------------------------------------
// Slash command registration
// ---------------------------------------------------------------------------

func registerSlashCommands() {
	if discordSession == nil || discordSession.State.User == nil {
		log.Println("⚠️ Discord user state is nil. Cannot register commands.")
		return
	}

	appID := discordSession.State.User.ID

	genExtraOpts := []*discordgo.ApplicationCommandOption{
		{Type: discordgo.ApplicationCommandOptionInteger, Name: "max_devices", Description: "Maximum number of devices (0 = unlimited)", Required: false},
		{Type: discordgo.ApplicationCommandOptionString, Name: "note", Description: "Optional note", Required: false},
		{Type: discordgo.ApplicationCommandOptionInteger, Name: "amount", Description: "Number of keys to generate (max 100)", Required: false},
	}

	genWithDays := append([]*discordgo.ApplicationCommandOption{
		{Type: discordgo.ApplicationCommandOptionInteger, Name: "days", Description: "Number of days until expiration", Required: false},
	}, genExtraOpts...)

	commandsList := []*discordgo.ApplicationCommand{
		{Name: "keys", Description: "📋 Display all licenses"},

		// SHADE keys (main checker)
		{Name: "gen", Description: "🔑 Generate SHADE keys", Options: genWithDays},
		{Name: "genlifetime", Description: "🔑 Generate lifetime SHADE keys", Options: genExtraOpts},

		// NINTENDO keys (Nintendo checker)
		{Name: "gennintendo", Description: "🔑 Generate NINTENDO keys", Options: genWithDays},
		{Name: "gennintendolifetime", Description: "🔑 Generate lifetime NINTENDO keys", Options: genExtraOpts},

		{
			Name: "reset", Description: "🔄 Reset HWID binding for a license",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "license_key", Description: "The license key to reset", Required: true},
			},
		},
		{
			Name: "unbind", Description: "🔓 Unbind a license from a Discord account",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "license_key", Description: "The license key to unbind", Required: true},
			},
		},
		{
			Name: "active", Description: "🟢 Show live sessions (key, HWID, IP, last seen)",
		},
		{
			Name: "blockip", Description: "⛔ Block an IP globally",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "ip", Description: "IP to block", Required: true},
				{Type: discordgo.ApplicationCommandOptionString, Name: "reason", Description: "Reason", Required: false},
			},
		},
		{
			Name: "unblockip", Description: "✅ Unblock an IP",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "ip", Description: "IP to unblock", Required: true},
			},
		},
		{
			Name: "blockhwid", Description: "⛔ Block an HWID globally",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "hwid", Description: "HWID to block", Required: true},
				{Type: discordgo.ApplicationCommandOptionString, Name: "reason", Description: "Reason", Required: false},
			},
		},
		{
			Name: "unblockhwid", Description: "✅ Unblock an HWID",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "hwid", Description: "HWID to unblock", Required: true},
			},
		},
		{
			Name: "bindip", Description: "🌐 Bind an IP/CIDR to a license (empty list = any IP)",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "license_key", Description: "The license key", Required: true},
				{Type: discordgo.ApplicationCommandOptionString, Name: "ip", Description: "IP or CIDR to allow (e.g. 1.2.3.4 or 10.0.0.0/24)", Required: true},
			},
		},
		{
			Name: "unbindip", Description: "🌐 Remove IP binding(s) from a license (no ip = clear all)",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "license_key", Description: "The license key", Required: true},
				{Type: discordgo.ApplicationCommandOptionString, Name: "ip", Description: "IP/CIDR to remove (omit to clear all)", Required: false},
			},
		},
		{
			Name: "del", Description: "🗑️ Delete a license permanently",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "license_key", Description: "The license key to delete", Required: true},
			},
		},
		{
			Name: "info", Description: "ℹ️ Get detailed information about a license",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "license_key", Description: "The license key to inspect", Required: true},
			},
		},
		{Name: "logs", Description: "📜 Show validation logs"},
		{Name: "suspicious", Description: "🚨 Show recent suspicious-activity reports"},

		// SHADE version
		{Name: "version", Description: "🔢 Check current required SHADE client version"},
		{
			Name: "setversion", Description: "📌 Set required SHADE client version",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "version", Description: "Version number (e.g., 1.2.2)", Required: true},
			},
		},

		// Nintendo version
		{Name: "versionnintendo", Description: "🔢 Check current required Nintendo client version"},
		{
			Name: "setnintendoversion", Description: "📌 Set required Nintendo client version",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "version", Description: "Version number (e.g., 1.2.3)", Required: true},
			},
		},

		{Name: "stats", Description: "📊 Show license system statistics"},
		{
			Name: "extend", Description: "📅 Extend license expiration by days",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "license_key", Description: "The license key to extend", Required: true},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "days", Description: "Number of days to add", Required: false},
			},
		},
		{
			Name: "expandall", Description: "📅 Extend all active licenses by days",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "days", Description: "Number of days to add to every active key", Required: true},
			},
		},
	}

	log.Println("Registering Discord slash commands...")
	if _, err := discordSession.ApplicationCommandBulkOverwrite(appID, DISCORD_GUILD_ID, commandsList); err != nil {
		log.Printf("⚠️ Failed to bulk overwrite commands: %v. Falling back to individual creation...", err)
		for _, cmd := range commandsList {
			if _, err := discordSession.ApplicationCommandCreate(appID, DISCORD_GUILD_ID, cmd); err != nil {
				log.Printf("❌ Failed to create command %s: %v", cmd.Name, err)
			} else {
				log.Printf("✅ Registered command: %s", cmd.Name)
			}
		}
	} else {
		log.Println("✅ Successfully registered all slash commands!")
	}
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

func handleSlashCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	adminID := DISCORD_ADMIN_ID
	if adminID == "" {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ Admin ID not configured on server."},
		})
		return
	}

	if i.Member == nil || i.Member.User == nil || i.Member.User.ID != adminID {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ **Access Denied!**\nYou don't have permission to use this command."},
		})
		return
	}

	switch i.ApplicationCommandData().Name {
	case "keys":
		cmdListKeys(s, i)
	case "gen":
		cmdGenKey(s, i)
	case "gennintendo":
		cmdGenNintendoKey(s, i)
	case "genlifetime":
		generateKeys(s, i, 0, true, "Lifetime", "SHADE-")
	case "gennintendolifetime":
		generateKeys(s, i, 0, true, "Lifetime", "NINTENDO-")
	case "reset":
		cmdResetHWID(s, i)
	case "unbind":
		cmdUnbind(s, i)
	case "active":
		cmdActive(s, i)
	case "blockip":
		cmdBlockIP(s, i)
	case "unblockip":
		cmdUnblockIP(s, i)
	case "blockhwid":
		cmdBlockHWID(s, i)
	case "unblockhwid":
		cmdUnblockHWID(s, i)
	case "bindip":
		cmdBindIP(s, i)
	case "unbindip":
		cmdUnbindIP(s, i)
	case "del":
		cmdDeleteKey(s, i)
	case "info":
		cmdKeyInfo(s, i)
	case "logs":
		cmdGetLogs(s, i)
	case "suspicious":
		cmdGetSuspicious(s, i)
	case "version":
		cmdGetVersionShade(s, i)
	case "setversion":
		cmdSetVersionShade(s, i)
	case "versionnintendo":
		cmdGetVersionNintendo(s, i)
	case "setnintendoversion":
		cmdSetVersionNintendo(s, i)
	case "stats":
		cmdGetStats(s, i)
	case "extend":
		cmdExtendLicense(s, i)
	case "expandall":
		cmdExpandAll(s, i)
	}
}

// ---------------------------------------------------------------------------
// /keys
// ---------------------------------------------------------------------------

func cmdListKeys(s *discordgo.Session, i *discordgo.InteractionCreate) {
	rows, err := db.Query(`
		SELECT id, license_key, expiry_days, max_devices, activated, note, created_at,
		       COALESCE(expiry_date, created_at + (expiry_days || ' days')::interval) as calc_expiry,
		       hwid, devices, resets, COALESCE(lifetime, false), COALESCE(discord_id,'')
		FROM licenses ORDER BY id DESC LIMIT 25
	`)
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ Failed to fetch licenses"},
		})
		return
	}
	defer rows.Close()

	var output strings.Builder
	output.WriteString("**📋 FULL LICENSE LIST**\n```\n")
	output.WriteString(fmt.Sprintf("%-4s %-25s %-8s %-6s %-10s %-15s %-8s %-10s %-20s\n",
		"ID", "KEY", "DAYS", "MAXDEV", "STATUS", "EXPIRES", "RESETS", "DEVICES", "DISCORD"))
	output.WriteString(strings.Repeat("-", 125) + "\n")

	for rows.Next() {
		var id int
		var key string
		var note, hwid, devicesJSON, discordID sql.NullString
		var days sql.NullInt64
		var maxDev, resets int
		var activated, lifetime bool
		var created time.Time
		var expiry sql.NullTime

		rows.Scan(&id, &key, &days, &maxDev, &activated, &note, &created, &expiry, &hwid, &devicesJSON, &resets, &lifetime, &discordID)

		daysLeft := 0
		expiryStr := "Not activated"
		daysCol := "NULL"
		if days.Valid {
			daysCol = fmt.Sprintf("%d", days.Int64)
		}
		if lifetime || !days.Valid || days.Int64 <= 0 {
			daysCol = "LIFE"
			lifetime = true
		}
		if activated {
			if lifetime {
				expiryStr = "Lifetime"
			} else {
				if expiry.Valid {
					daysLeft = int(time.Until(expiry.Time).Hours() / 24)
				}
				expiryStr = fmt.Sprintf("%dd", daysLeft)
				if daysLeft < 0 {
					expiryStr = "EXPIRED"
				}
			}
		}

		var devicesCount int
		if devicesJSON.Valid && devicesJSON.String != "" && devicesJSON.String != "[]" {
			var devices []string
			json.Unmarshal([]byte(devicesJSON.String), &devices)
			devicesCount = len(devices)
		}

		status := "INACTIVE"
		if activated {
			status = "ACTIVE"
		}

		discordStr := "—"
		if discordID.Valid && discordID.String != "" {
			discordStr = discordID.String
		}

		output.WriteString(fmt.Sprintf("%-4d %-25s %-8s %-6d %-10s %-15s %-8d %-10d %-20s\n",
			id, key, daysCol, maxDev, status, expiryStr, resets, devicesCount, discordStr))
	}
	output.WriteString("```")

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: output.String()},
	})
}

// ---------------------------------------------------------------------------
// /gen  → SHADE keys
// ---------------------------------------------------------------------------

func cmdGenKey(s *discordgo.Session, i *discordgo.InteractionCreate) {
	days := 30
	for _, opt := range i.ApplicationCommandData().Options {
		if opt.Name == "days" {
			days = int(opt.IntValue())
		}
	}
	generateKeys(s, i, days, false, "", "SHADE-")
}

// ---------------------------------------------------------------------------
// /gennintendo  → NINTENDO keys
// ---------------------------------------------------------------------------

func cmdGenNintendoKey(s *discordgo.Session, i *discordgo.InteractionCreate) {
	days := 30
	for _, opt := range i.ApplicationCommandData().Options {
		if opt.Name == "days" {
			days = int(opt.IntValue())
		}
	}
	generateKeys(s, i, days, false, "", "NINTENDO-")
}

// ---------------------------------------------------------------------------
// shared generation
// ---------------------------------------------------------------------------

func generateKeys(s *discordgo.Session, i *discordgo.InteractionCreate,
	days int, lifetime bool, durationLabel string, prefix string) {

	maxDevices := 1
	note := ""
	amount := 1

	for _, opt := range i.ApplicationCommandData().Options {
		switch opt.Name {
		case "max_devices":
			maxDevices = int(opt.IntValue())
		case "note":
			note = opt.StringValue()
		case "amount":
			amount = int(opt.IntValue())
		}
	}

	if lifetime {
		days = 0
	} else {
		if days <= 0 {
			days = 30
		}
		if days > 365 {
			days = 365
		}
	}
	if maxDevices < 0 {
		maxDevices = 0
	}
	if maxDevices > 999 {
		maxDevices = 999
	}
	if amount < 1 {
		amount = 1
	}
	if amount > 100 {
		amount = 100
	}
	if note == "" {
		note = "No note"
	}
	if durationLabel == "" {
		durationLabel = fmt.Sprintf("%d days", days)
	}
	if prefix == "" {
		prefix = "SHADE-"
	}

	var generatedKeys []string
	var errors []string

	for n := 0; n < amount; n++ {
		licenseKey := prefix + strings.ToUpper(uuid.New().String()[:5]) + "-" +
			strings.ToUpper(uuid.New().String()[:5]) + "-" +
			strings.ToUpper(uuid.New().String()[:5])

		var err error
		if lifetime {
			_, err = db.Exec(`
				INSERT INTO licenses (license_key, expiry_days, note, max_devices, created_at, lifetime, expiry_date)
				VALUES ($1, NULL, $2, $3, NOW(), TRUE, NULL)
			`, licenseKey, note, maxDevices)
		} else {
			_, err = db.Exec(`
				INSERT INTO licenses (license_key, expiry_days, note, max_devices, created_at, lifetime)
				VALUES ($1, $2, $3, $4, NOW(), FALSE)
			`, licenseKey, days, note, maxDevices)
		}

		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to create key %d: %v", n+1, err))
			continue
		}

		generatedKeys = append(generatedKeys, licenseKey)
		addLogAndDiscord(licenseKey, "CREATED", "Discord", "",
			fmt.Sprintf("Created by admin | Duration: %s | MaxDevices: %d | Note: %s", durationLabel, maxDevices, note))
	}

	if len(generatedKeys) == 0 {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ Failed to generate keys: %s", strings.Join(errors, "\n"))},
		})
		return
	}

	deviceLimit := fmt.Sprintf("%d", maxDevices)
	if maxDevices == 0 {
		deviceLimit = "♾️ Unlimited"
	}

	msg := fmt.Sprintf("**🔑 NEW KEYS GENERATED**\n\n```\nAmount: %d\nPrefix: %s\nValid for: %s\nMax Devices: %s\nNote: %s\n\nGenerated Keys:\n%s\n```",
		len(generatedKeys), prefix, durationLabel, deviceLimit, note, strings.Join(generatedKeys, "\n"))

	if len(errors) > 0 {
		msg += fmt.Sprintf("\n\n⚠️ Errors:\n%s", strings.Join(errors, "\n"))
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: msg},
	})
}

// ---------------------------------------------------------------------------
// /reset
// ---------------------------------------------------------------------------

func cmdResetHWID(s *discordgo.Session, i *discordgo.InteractionCreate) {
	licenseKey := normalizeLicenseKey(i.ApplicationCommandData().Options[0].StringValue())

	var note, hwid sql.NullString
	db.QueryRow(`SELECT note, hwid FROM licenses WHERE lower(license_key) = lower($1)`, licenseKey).Scan(&note, &hwid)

	result, err := db.Exec(`
		UPDATE licenses
		SET hwid = NULL, devices = '[]', resets = resets + 1
		WHERE lower(license_key) = lower($1)
	`, licenseKey)

	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ Failed to reset HWID: %v", err)},
		})
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ License not found."},
		})
		return
	}

	addLogAndDiscord(licenseKey, "HWID_RESET", "Discord", hwid.String, fmt.Sprintf("Reset by admin | Note: %s", note.String))

	msg := fmt.Sprintf("**🔄 HWID RESET COMPLETED**\n\n```\nLicense Key: %s\nStatus: Reset successful\nOld HWID: %s\n```", licenseKey, hwid.String)

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: msg},
	})
}

// ---------------------------------------------------------------------------
// /unbind
// ---------------------------------------------------------------------------

func cmdUnbind(s *discordgo.Session, i *discordgo.InteractionCreate) {
	licenseKey := normalizeLicenseKey(i.ApplicationCommandData().Options[0].StringValue())

	var discordID sql.NullString
	_ = db.QueryRow(`SELECT COALESCE(discord_id,'') FROM licenses WHERE lower(license_key) = lower($1)`, licenseKey).Scan(&discordID)

	res, err := db.Exec(`UPDATE licenses SET discord_id = '', redeemed_at = NULL WHERE lower(license_key) = lower($1)`, licenseKey)
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ %v", err)},
		})
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ License not found."},
		})
		return
	}

	addLogAndDiscord(licenseKey, "UNBIND", "Discord", "", fmt.Sprintf("Discord binding cleared (was %s)", discordID.String))

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("**🔓 LICENSE UNBOUND**\n\n```\nLicense Key: %s\nPrevious Discord: %s\n```", licenseKey, discordID.String),
		},
	})
}

// ---------------------------------------------------------------------------
// /bindip + /unbindip
// ---------------------------------------------------------------------------

func cmdBindIP(s *discordgo.Session, i *discordgo.InteractionCreate) {
	opts := i.ApplicationCommandData().Options
	licenseKey := normalizeLicenseKey(opts[0].StringValue())
	ip := strings.TrimSpace(opts[1].StringValue())

	if _, _, err := net.ParseCIDR(ip); err != nil {
		if net.ParseIP(ip) == nil {
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{Content: "❌ Invalid IP or CIDR."},
			})
			return
		}
	}

	var raw sql.NullString
	if err := db.QueryRow(`SELECT COALESCE(allowed_ips,'[]') FROM licenses WHERE lower(license_key) = lower($1)`, licenseKey).Scan(&raw); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ License not found."},
		})
		return
	}
	list := parseAllowedIPs(raw)
	for _, e := range list {
		if e == ip {
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("ℹ️ %s already bound.", ip)},
			})
			return
		}
	}
	list = append(list, ip)
	blob, _ := json.Marshal(list)
	if _, err := db.Exec(`UPDATE licenses SET allowed_ips = $1 WHERE lower(license_key) = lower($2)`, string(blob), licenseKey); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ %v", err)},
		})
		return
	}
	addLogAndDiscord(licenseKey, "IP_BOUND", "Discord", "", fmt.Sprintf("Bound %s", ip))
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("**🌐 IP BOUND**\n```\nKey: %s\nIP: %s\nAll: %s\n```", licenseKey, ip, strings.Join(list, ", "))},
	})
}

func cmdUnbindIP(s *discordgo.Session, i *discordgo.InteractionCreate) {
	opts := i.ApplicationCommandData().Options
	licenseKey := normalizeLicenseKey(opts[0].StringValue())
	ip := ""
	if len(opts) > 1 {
		ip = strings.TrimSpace(opts[1].StringValue())
	}

	var raw sql.NullString
	if err := db.QueryRow(`SELECT COALESCE(allowed_ips,'[]') FROM licenses WHERE lower(license_key) = lower($1)`, licenseKey).Scan(&raw); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ License not found."},
		})
		return
	}
	list := parseAllowedIPs(raw)
	if ip == "" {
		list = nil
	} else {
		kept := list[:0]
		for _, e := range list {
			if e != ip {
				kept = append(kept, e)
			}
		}
		list = kept
	}
	blob := "[]"
	if len(list) > 0 {
		b, _ := json.Marshal(list)
		blob = string(b)
	}
	if _, err := db.Exec(`UPDATE licenses SET allowed_ips = $1 WHERE lower(license_key) = lower($2)`, blob, licenseKey); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ %v", err)},
		})
		return
	}
	shown := strings.Join(list, ", ")
	if shown == "" {
		shown = "(any IP)"
	}
	addLogAndDiscord(licenseKey, "IP_UNBOUND", "Discord", "", fmt.Sprintf("Remaining: %s", shown))
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("**🌐 IP BINDINGS UPDATED**\n```\nKey: %s\nAllowed now: %s\n```", licenseKey, shown)},
	})
}

// ---------------------------------------------------------------------------
// /active + IP/HWID blocklists
// ---------------------------------------------------------------------------

func optStr(i *discordgo.InteractionCreate, idx int) string {
	opts := i.ApplicationCommandData().Options
	if idx < len(opts) {
		return strings.TrimSpace(opts[idx].StringValue())
	}
	return ""
}

func cmdActive(s *discordgo.Session, i *discordgo.InteractionCreate) {
	sess := listLiveSessions()
	var b strings.Builder
	b.WriteString("**🟢 LIVE SESSIONS**\n```\n")
	if len(sess) == 0 {
		b.WriteString("(none in the last 40 min)\n")
	} else {
		b.WriteString(fmt.Sprintf("%-28s %-20s %-16s %s\n", "KEY", "HWID", "IP", "SEEN"))
		for _, v := range sess {
			hw := v.HWID
			if len(hw) > 18 {
				hw = hw[:18]
			}
			b.WriteString(fmt.Sprintf("%-28s %-20s %-16s %ds ago\n",
				v.License, hw, v.IP, int(time.Since(v.Seen).Seconds())))
		}
	}
	b.WriteString("```")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: b.String()},
	})
}

func cmdBlockIP(s *discordgo.Session, i *discordgo.InteractionCreate) {
	ip := optStr(i, 0)
	reason := optStr(i, 1)
	if net.ParseIP(ip) == nil {
		respondErr(s, i, "Invalid IP.")
		return
	}
	if _, err := db.Exec(`INSERT INTO blocked_ips (ip, reason) VALUES ($1, $2)
		ON CONFLICT (ip) DO UPDATE SET reason = EXCLUDED.reason`, ip, reason); err != nil {
		respondErr(s, i, fmt.Sprintf("%v", err))
		return
	}
	addLogAndDiscord("", "IP_BLOCKED", ip, "", fmt.Sprintf("Blocked by admin | %s", reason))
	respondOK(s, i, fmt.Sprintf("**⛔ IP BLOCKED**\n```\n%s\n```", ip))
}

func cmdUnblockIP(s *discordgo.Session, i *discordgo.InteractionCreate) {
	ip := optStr(i, 0)
	res, err := db.Exec(`DELETE FROM blocked_ips WHERE ip = $1`, ip)
	if err != nil {
		respondErr(s, i, fmt.Sprintf("%v", err))
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		respondErr(s, i, "IP was not blocked.")
		return
	}
	addLogAndDiscord("", "IP_UNBLOCKED", ip, "", "Unblocked by admin")
	respondOK(s, i, fmt.Sprintf("**✅ IP UNBLOCKED**\n```\n%s\n```", ip))
}

func cmdBlockHWID(s *discordgo.Session, i *discordgo.InteractionCreate) {
	hwid := normalizeHWID(optStr(i, 0))
	reason := optStr(i, 1)
	if hwid == "" {
		respondErr(s, i, "Invalid HWID.")
		return
	}
	if _, err := db.Exec(`INSERT INTO blocked_hwids (hwid, reason) VALUES ($1, $2)
		ON CONFLICT (hwid) DO UPDATE SET reason = EXCLUDED.reason`, hwid, reason); err != nil {
		respondErr(s, i, fmt.Sprintf("%v", err))
		return
	}
	addLogAndDiscord("", "HWID_BLOCKED", "", hwid, fmt.Sprintf("Blocked by admin | %s", reason))
	respondOK(s, i, fmt.Sprintf("**⛔ HWID BLOCKED**\n```\n%s\n```", hwid))
}

func cmdUnblockHWID(s *discordgo.Session, i *discordgo.InteractionCreate) {
	hwid := normalizeHWID(optStr(i, 0))
	res, err := db.Exec(`DELETE FROM blocked_hwids WHERE hwid = $1`, hwid)
	if err != nil {
		respondErr(s, i, fmt.Sprintf("%v", err))
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		respondErr(s, i, "HWID was not blocked.")
		return
	}
	addLogAndDiscord("", "HWID_UNBLOCKED", "", hwid, "Unblocked by admin")
	respondOK(s, i, fmt.Sprintf("**✅ HWID UNBLOCKED**\n```\n%s\n```", hwid))
}

func respondErr(s *discordgo.Session, i *discordgo.InteractionCreate, msg string) {
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: "❌ " + msg},
	})
}

func respondOK(s *discordgo.Session, i *discordgo.InteractionCreate, msg string) {
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: msg},
	})
}

// ---------------------------------------------------------------------------
// /del
// ---------------------------------------------------------------------------

func cmdDeleteKey(s *discordgo.Session, i *discordgo.InteractionCreate) {
	licenseKey := normalizeLicenseKey(i.ApplicationCommandData().Options[0].StringValue())

	var note sql.NullString
	if err := db.QueryRow(`SELECT note FROM licenses WHERE lower(license_key) = lower($1)`, licenseKey).Scan(&note); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ License not found."},
		})
		return
	}

	result, err := db.Exec(`DELETE FROM licenses WHERE lower(license_key) = lower($1)`, licenseKey)
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ Failed to delete: %v", err)},
		})
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ License not found."},
		})
		return
	}

	addLogAndDiscord(licenseKey, "DELETED", "Discord", "", fmt.Sprintf("Deleted by admin | Note: %s", note.String))

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("**🗑️ LICENSE DELETED**\n\n```\nLicense Key: %s\n```", licenseKey)},
	})
}

// ---------------------------------------------------------------------------
// /info
// ---------------------------------------------------------------------------

func cmdKeyInfo(s *discordgo.Session, i *discordgo.InteractionCreate) {
	licenseKey := i.ApplicationCommandData().Options[0].StringValue()

	var id int
	var key string
	var note, hwid, devicesJSON, discordID sql.NullString
	var days sql.NullInt64
	var maxDev, resets int
	var activated, lifetime bool
	var expiryDate, createdAt, activatedAt, redeemedAt sql.NullTime

	err := db.QueryRow(`
		SELECT id, license_key, expiry_days, note, max_devices, activated, hwid, devices, resets, created_at, expiry_date, activated_at, COALESCE(lifetime, false), COALESCE(discord_id,''), redeemed_at
		FROM licenses WHERE license_key = $1
	`, licenseKey).Scan(&id, &key, &days, &note, &maxDev, &activated, &hwid, &devicesJSON, &resets, &createdAt, &expiryDate, &activatedAt, &lifetime, &discordID, &redeemedAt)

	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ License `%s` not found.", licenseKey)},
		})
		return
	}

	var devices []string
	if devicesJSON.Valid && devicesJSON.String != "" && devicesJSON.String != "[]" {
		json.Unmarshal([]byte(devicesJSON.String), &devices)
	}

	daysLeft := 0
	expiryStr := "Not set"
	validFor := "Lifetime"
	if days.Valid && days.Int64 > 0 && !lifetime {
		validFor = fmt.Sprintf("%d days", days.Int64)
	}
	if lifetime || !days.Valid || days.Int64 <= 0 {
		lifetime = true
		validFor = "Lifetime"
		expiryStr = "Never"
	} else if expiryDate.Valid {
		daysLeft = int(time.Until(expiryDate.Time).Hours() / 24)
		if daysLeft > 0 {
			expiryStr = fmt.Sprintf("%d days left", daysLeft)
		} else if daysLeft == 0 {
			expiryStr = "Expires today!"
		} else {
			expiryStr = "EXPIRED"
		}
	}

	statusEmoji := "🔴"
	statusText := "INACTIVE"
	if activated {
		statusEmoji = "🟢"
		statusText = "ACTIVE"
	}
	if !lifetime && expiryDate.Valid && daysLeft < 0 {
		statusEmoji = "⚫"
		statusText = "EXPIRED"
	}

	deviceLimitText := fmt.Sprintf("%d", maxDev)
	if maxDev == 0 {
		deviceLimitText = "♾️ Unlimited"
	}

	hwidText := "Not bound"
	if hwid.Valid && hwid.String != "" && len(hwid.String) > 10 {
		hwidText = hwid.String
	}

	discordText := "Not redeemed"
	if discordID.Valid && discordID.String != "" {
		discordText = fmt.Sprintf("<@%s> (`%s`)", discordID.String, discordID.String)
	}

	redeemedText := "—"
	if redeemedAt.Valid {
		redeemedText = redeemedAt.Time.Format("2006-01-02 15:04")
	}

	msg := fmt.Sprintf("**ℹ️ FULL LICENSE INFORMATION**\n\n```\nID: %d\nLicense Key: %s\nStatus: %s %s\nCreated: %s\nValid for: %s\nExpires: %s\nMax Devices: %s\nDevices Used: %d\nHWID: %s\nResets: %d\nNote: %s\nDiscord: %s\nRedeemed: %s\n```",
		id, key, statusEmoji, statusText, createdAt.Time.Format("2006-01-02"), validFor, expiryStr,
		deviceLimitText, len(devices), hwidText, resets, note.String, discordText, redeemedText)

	if len(devices) > 0 {
		msg += "\n**📱 Registered Devices:**\n```"
		for i, d := range devices {
			msg += fmt.Sprintf("\n%d: %s", i+1, d)
		}
		msg += "```"
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: msg},
	})
}

// ---------------------------------------------------------------------------
// /logs
// ---------------------------------------------------------------------------

func cmdGetLogs(s *discordgo.Session, i *discordgo.InteractionCreate) {
	rows, err := db.Query(`
		SELECT id, license_key, action, ip_address, timestamp, hwid, details
		FROM logs ORDER BY timestamp DESC LIMIT 50
	`)
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ Failed to fetch logs"},
		})
		return
	}
	defer rows.Close()

	var output strings.Builder
	output.WriteString("**📜 RECENT LOGS (Last 50)**\n```\n")
	output.WriteString(fmt.Sprintf("%-4s %-20s %-15s %-20s %-20s %-20s\n",
		"ID", "KEY", "ACTION", "IP", "HWID", "DETAILS"))
	output.WriteString(strings.Repeat("-", 105) + "\n")

	for rows.Next() {
		var id int
		var key, action, ip, hwid, details sql.NullString
		var timestamp time.Time

		rows.Scan(&id, &key, &action, &ip, &timestamp, &hwid, &details)

		shortKey := key.String
		if len(shortKey) > 20 {
			shortKey = shortKey[:17] + "..."
		}
		shortHwid := hwid.String
		if len(shortHwid) > 20 {
			shortHwid = shortHwid[:17] + "..."
		}
		shortDetails := details.String
		if len(shortDetails) > 20 {
			shortDetails = shortDetails[:17] + "..."
		}
		shortIP := ip.String
		if len(shortIP) > 20 {
			shortIP = shortIP[:17] + "..."
		}

		output.WriteString(fmt.Sprintf("%-4d %-20s %-15s %-20s %-20s %-20s\n",
			id, shortKey, action.String, shortIP, shortHwid, shortDetails))
	}
	output.WriteString("```")

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: output.String()},
	})
}

// ---------------------------------------------------------------------------
// /suspicious — recent anti-tamper reports
// ---------------------------------------------------------------------------

func cmdGetSuspicious(s *discordgo.Session, i *discordgo.InteractionCreate) {
	rows, err := db.Query(`
		SELECT id, license_key, action, ip_address, timestamp, hwid, details
		FROM logs
		WHERE action LIKE 'SUSPICIOUS_%'
		ORDER BY timestamp DESC LIMIT 25
	`)
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ Failed to fetch suspicious logs"},
		})
		return
	}
	defer rows.Close()

	var b strings.Builder
	b.WriteString("**🚨 RECENT SUSPICIOUS ACTIVITY (Last 25)**\n```\n")
	b.WriteString(fmt.Sprintf("%-4s %-22s %-20s %-18s %-19s\n",
		"ID", "KIND", "HWID", "IP", "WHEN"))
	b.WriteString(strings.Repeat("-", 90) + "\n")

	n := 0
	for rows.Next() {
		var id int
		var key, action, ip, hwid, details sql.NullString
		var ts time.Time
		rows.Scan(&id, &key, &action, &ip, &ts, &hwid, &details)

		kind := strings.TrimPrefix(action.String, "SUSPICIOUS_")

		shortHW := hwid.String
		if len(shortHW) > 18 {
			shortHW = shortHW[:18]
		}
		shortIP := ip.String
		if len(shortIP) > 18 {
			shortIP = shortIP[:18]
		}

		b.WriteString(fmt.Sprintf("%-4d %-22s %-20s %-18s %-19s\n",
			id,
			truncateStr(kind, 22),
			shortHW,
			shortIP,
			ts.Format("2006-01-02 15:04:05"),
		))
		n++
	}
	if n == 0 {
		b.WriteString("(none)\n")
	}
	b.WriteString("```")

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: b.String()},
	})
}

// ---------------------------------------------------------------------------
// /version, /setversion  (SHADE — uses `versions` table)
// ---------------------------------------------------------------------------

func cmdGetVersionShade(s *discordgo.Session, i *discordgo.InteractionCreate) {
	var version string
	var createdAt sql.NullTime

	err := db.QueryRow(
		`SELECT version, created_at FROM versions WHERE is_active = TRUE ORDER BY id DESC LIMIT 1`,
	).Scan(&version, &createdAt)
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ No active SHADE version row."},
		})
		return
	}

	createdStr := "Unknown"
	if createdAt.Valid {
		createdStr = createdAt.Time.Format("2006-01-02 15:04:05")
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("**🔢 REQUIRED CLIENT VERSION — SHADE**\n\n```\nVersion: %s\nSet on:  %s\n```",
				version, createdStr),
		},
	})
}

func cmdSetVersionShade(s *discordgo.Session, i *discordgo.InteractionCreate) {
	newVersion := i.ApplicationCommandData().Options[0].StringValue()

	tx, err := db.Begin()
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ %v", err)},
		})
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`UPDATE versions SET is_active = FALSE`); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ %v", err)},
		})
		return
	}
	if _, err := tx.Exec(
		`INSERT INTO versions (version, is_active, created_at) VALUES ($1, TRUE, NOW())`,
		newVersion,
	); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ %v", err)},
		})
		return
	}
	if err := tx.Commit(); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ %v", err)},
		})
		return
	}

	addLogAndDiscord("SYSTEM", "VERSION_CHANGED", "Discord", "",
		fmt.Sprintf("SHADE version → %s", newVersion))

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("**📌 SHADE VERSION UPDATED**\n\n```\nNew required version: %s\n```", newVersion),
		},
	})
}

// ---------------------------------------------------------------------------
// /versionnintendo, /setnintendoversion  (Nintendo — uses `nintendo_versions`)
// ---------------------------------------------------------------------------

func cmdGetVersionNintendo(s *discordgo.Session, i *discordgo.InteractionCreate) {
	var version string
	var createdAt sql.NullTime

	err := db.QueryRow(
		`SELECT version, created_at FROM nintendo_versions WHERE is_active = TRUE ORDER BY id DESC LIMIT 1`,
	).Scan(&version, &createdAt)
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ No active Nintendo version row."},
		})
		return
	}

	createdStr := "Unknown"
	if createdAt.Valid {
		createdStr = createdAt.Time.Format("2006-01-02 15:04:05")
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("**🔢 REQUIRED CLIENT VERSION — NINTENDO**\n\n```\nVersion: %s\nSet on:  %s\n```",
				version, createdStr),
		},
	})
}

func cmdSetVersionNintendo(s *discordgo.Session, i *discordgo.InteractionCreate) {
	newVersion := i.ApplicationCommandData().Options[0].StringValue()

	tx, err := db.Begin()
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ %v", err)},
		})
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`UPDATE nintendo_versions SET is_active = FALSE`); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ %v", err)},
		})
		return
	}
	if _, err := tx.Exec(
		`INSERT INTO nintendo_versions (version, is_active, created_at) VALUES ($1, TRUE, NOW())`,
		newVersion,
	); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ %v", err)},
		})
		return
	}
	if err := tx.Commit(); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ %v", err)},
		})
		return
	}

	addLogAndDiscord("SYSTEM", "VERSION_CHANGED", "Discord", "",
		fmt.Sprintf("Nintendo version → %s", newVersion))

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("**📌 NINTENDO VERSION UPDATED**\n\n```\nNew required version: %s\n```", newVersion),
		},
	})
}

// ---------------------------------------------------------------------------
// /stats
// ---------------------------------------------------------------------------

func cmdGetStats(s *discordgo.Session, i *discordgo.InteractionCreate) {
	var total, active, expired, hwidBound int
	db.QueryRow(`SELECT COUNT(*) FROM licenses`).Scan(&total)
	db.QueryRow(`SELECT COUNT(*) FROM licenses WHERE activated = true AND expiry_date > NOW()`).Scan(&active)
	db.QueryRow(`SELECT COUNT(*) FROM licenses WHERE expiry_date < NOW()`).Scan(&expired)
	db.QueryRow(`SELECT COUNT(*) FROM licenses WHERE hwid != ''`).Scan(&hwidBound)

	var todayChecks int
	db.QueryRow(`SELECT COUNT(*) FROM logs WHERE DATE(timestamp) = CURRENT_DATE`).Scan(&todayChecks)

	var totalDevices int
	db.QueryRow(`SELECT COALESCE(SUM(json_array_length(devices::json)), 0) FROM licenses WHERE devices != '[]' AND devices != '' AND devices IS NOT NULL`).Scan(&totalDevices)

	var invalidAttempts int
	db.QueryRow(`SELECT COUNT(*) FROM logs WHERE action IN ('INVALID_KEY', 'HWID_MISMATCH', 'EXPIRED') AND DATE(timestamp) = CURRENT_DATE`).Scan(&invalidAttempts)

	var redeemed int
	db.QueryRow(`SELECT COUNT(*) FROM licenses WHERE discord_id != ''`).Scan(&redeemed)

	var suspiciousToday int
	db.QueryRow(`SELECT COUNT(*) FROM logs WHERE action LIKE 'SUSPICIOUS_%' AND DATE(timestamp) = CURRENT_DATE`).Scan(&suspiciousToday)

	shadeVersion := lookupShadeVersion()
	nintendoVersion := lookupNintendoVersion()

	msg := fmt.Sprintf("**📊 LICENSE SYSTEM STATISTICS**\n\n```\n"+
		"Total Licenses:     %d\n"+
		"Active Licenses:    %d\n"+
		"Expired Licenses:   %d\n"+
		"HWID Bound:         %d\n"+
		"Discord Redeemed:   %d\n"+
		"Total Devices:      %d\n"+
		"Today's Checks:     %d\n"+
		"Invalid Attempts:   %d\n"+
		"Suspicious (today): %d\n"+
		"\n"+
		"SHADE version:      %s\n"+
		"Nintendo version:   %s\n"+
		"```",
		total, active, expired, hwidBound, redeemed, totalDevices,
		todayChecks, invalidAttempts, suspiciousToday,
		shadeVersion, nintendoVersion)

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: msg},
	})
}

// ---------------------------------------------------------------------------
// /extend
// ---------------------------------------------------------------------------

func cmdExtendLicense(s *discordgo.Session, i *discordgo.InteractionCreate) {
	licenseKey := i.ApplicationCommandData().Options[0].StringValue()
	days := 30
	if len(i.ApplicationCommandData().Options) > 1 {
		days = int(i.ApplicationCommandData().Options[1].IntValue())
	}
	if days <= 0 {
		days = 30
	}
	if days > 365 {
		days = 365
	}

	var currentExpiry sql.NullTime
	var currentDays sql.NullInt64
	var note sql.NullString
	var lifetime bool

	if err := db.QueryRow(`SELECT expiry_date, expiry_days, note, COALESCE(lifetime, false) FROM licenses WHERE license_key = $1`, licenseKey).Scan(&currentExpiry, &currentDays, &note, &lifetime); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ License `%s` not found.", licenseKey)},
		})
		return
	}
	if lifetime || !currentDays.Valid || currentDays.Int64 <= 0 {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "♾️ This key is already lifetime — no expiry to extend."},
		})
		return
	}

	var newExpiry time.Time
	if currentExpiry.Valid {
		newExpiry = currentExpiry.Time.AddDate(0, 0, days)
	} else {
		newExpiry = time.Now().AddDate(0, 0, int(currentDays.Int64)+days)
	}

	_, err := db.Exec(`UPDATE licenses SET expiry_date = $1, expiry_days = expiry_days + $2 WHERE license_key = $3`, newExpiry, days, licenseKey)
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ Failed to extend license: %v", err)},
		})
		return
	}

	addLogAndDiscord(licenseKey, "EXTENDED", "Discord", "",
		fmt.Sprintf("Added %d days | New expiry: %s | Note: %s", days, newExpiry.Format("2006-01-02"), note.String))

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("**📅 LICENSE EXTENDED**\n\n```\nLicense Key: %s\nAdded: %d days\nNew Expiry: %s\n```", licenseKey, days, newExpiry.Format("2006-01-02"))},
	})
}

// ---------------------------------------------------------------------------
// /expandall
// ---------------------------------------------------------------------------

func cmdExpandAll(s *discordgo.Session, i *discordgo.InteractionCreate) {
	days := int(i.ApplicationCommandData().Options[0].IntValue())

	if days <= 0 {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: "❌ Days must be greater than 0."},
		})
		return
	}
	if days > 365 {
		days = 365
	}

	result, err := db.Exec(`
		UPDATE licenses
		SET expiry_date = expiry_date + ($1 * INTERVAL '1 day'),
		    expiry_days = expiry_days + $1
		WHERE activated = true AND COALESCE(lifetime, false) = false AND expiry_date IS NOT NULL AND expiry_date > NOW()
	`, days)
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("❌ Failed to expand licenses: %v", err)},
		})
		return
	}

	rows, _ := result.RowsAffected()

	addLogAndDiscord("SYSTEM", "EXTENDED", "Discord", "", fmt.Sprintf("Expanded all active keys by %d days | Keys updated: %d", days, rows))

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: fmt.Sprintf("**📅 ALL ACTIVE KEYS EXTENDED**\n\n```\nAdded: %d days\nKeys updated: %d\n```", days, rows)},
	})
}