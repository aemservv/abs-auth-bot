package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

const threadCleanupDelay = 15 * time.Minute
const uploadWaitFor = 5 * time.Minute

var (
	customerSession *discordgo.Session

	uploadWait      = make(map[string]time.Time)
	uploadWaitMutex sync.Mutex
)

func initCustomerBot() {
	token := DISCORD_CUSTOMER_BOT_TOKEN
	if token == "" {
		log.Println("⚠️ DISCORD_CUSTOMER_BOT_TOKEN is empty. Customer bot disabled.")
		return
	}

	var err error
	customerSession, err = discordgo.New("Bot " + token)
	if err != nil {
		log.Printf("⚠️ Customer bot failed to start: %v", err)
		return
	}

	customerSession.Identify.Intents = discordgo.IntentsGuildMessages |
		discordgo.IntentsGuildMembers |
		discordgo.IntentsMessageContent

	customerSession.AddHandler(func(s *discordgo.Session, i *discordgo.InteractionCreate) {
		if i.Type == discordgo.InteractionApplicationCommand {
			handleCustomerCommand(s, i)
		}
	})

	customerSession.AddHandler(func(s *discordgo.Session, m *discordgo.MessageCreate) {
		handleUploadMessage(s, m)
	})

	if err = customerSession.Open(); err != nil {
		log.Printf("⚠️ Customer bot failed to connect: %v", err)
		return
	}

	registerCustomerCommands()
	log.Println("✅ Customer bot is running!")
}

func registerCustomerCommands() {
	if customerSession == nil || customerSession.State.User == nil {
		return
	}
	appID := customerSession.State.User.ID
	log.Printf("📝 Customer bot app ID: %s", appID)

	adminPerms := int64(0)

	cmds := []*discordgo.ApplicationCommand{
		{
			Name:        "redeem",
			Description: "🔑 Redeem your license key",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "license_key",
					Description: "Your license key (e.g. NINTENDO-XXXXX-XXXXX-XXXXX)",
					Required:    true,
				},
			},
		},
		{
			Name:        "loader",
			Description: "📥 Receive the loader in a private thread",
		},
		{
			Name:        "status",
			Description: "📊 Show your current license status",
		},
		{
			Name:                     "upload",
			Description:              "📤 [ADMIN] Upload a new loader.exe to the server",
			DefaultMemberPermissions: &adminPerms,
		},
	}

	guildID := DISCORD_CUSTOMER_GUILD_ID
	if guildID == "" {
		log.Println("⚠️ DISCORD_CUSTOMER_GUILD_ID not set; registering global commands (may take up to 1h).")
	}
	if _, err := customerSession.ApplicationCommandBulkOverwrite(appID, guildID, cmds); err != nil {
		log.Printf("❌ Failed to register customer commands: %v", err)
	} else {
		log.Println("✅ Customer bot commands registered (redeem, loader, status, upload)")
	}
}

func handleCustomerCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	name := i.ApplicationCommandData().Name

	if name == "upload" {
		if i.Member == nil || i.Member.User == nil || i.Member.User.ID != DISCORD_ADMIN_ID {
			respondEphemeral(s, i, "❌ Access denied.")
			return
		}
		cmdUpload(s, i)
		return
	}

	if !customerChannelAllowed(i.ChannelID) {
		respondEphemeral(s, i, "❌ This command can only be used in the designated commands channel.")
		return
	}

	switch name {
	case "redeem":
		cmdRedeem(s, i)
	case "loader":
		cmdLoader(s, i)
	case "status":
		cmdStatus(s, i)
	}
}

// ---------- /upload ----------

func cmdUpload(s *discordgo.Session, i *discordgo.InteractionCreate) {
	uploadWaitMutex.Lock()
	uploadWait[i.Member.User.ID] = time.Now().Add(uploadWaitFor)
	uploadWaitMutex.Unlock()

	log.Printf("📤 /upload armed for admin %s (expires in %s)", i.Member.User.ID, uploadWaitFor)

	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Flags: discordgo.MessageFlagsEphemeral,
			Content: fmt.Sprintf(
				"**📤 Loader upload armed**\n\n"+
					"Within the next **5 minutes**, drop a `.exe` file in **this channel** and it will replace the current loader.\n\n"+
					"Saved to server as: `%s`",
				LoaderFilePath,
			),
		},
	})
}

func handleUploadMessage(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author == nil {
		return
	}
	if m.Author.ID != DISCORD_ADMIN_ID {
		return
	}
	if len(m.Attachments) == 0 {
		return
	}

	uploadWaitMutex.Lock()
	expiry, armed := uploadWait[m.Author.ID]
	uploadWaitMutex.Unlock()

	if !armed {
		return
	}
	if time.Now().After(expiry) {
		uploadWaitMutex.Lock()
		delete(uploadWait, m.Author.ID)
		uploadWaitMutex.Unlock()
		return
	}

	var exeAttachment *discordgo.MessageAttachment
	for _, att := range m.Attachments {
		if strings.HasSuffix(strings.ToLower(att.Filename), ".exe") {
			exeAttachment = att
			break
		}
	}
	if exeAttachment == nil {
		return
	}

	uploadWaitMutex.Lock()
	delete(uploadWait, m.Author.ID)
	uploadWaitMutex.Unlock()

	log.Printf("[DEBUG] downloading attachment: %s (%d bytes) from %s",
		exeAttachment.Filename, exeAttachment.Size, exeAttachment.URL)

	resp, err := http.Get(exeAttachment.URL)
	if err != nil {
		log.Printf("[ERROR] download loader: %v", err)
		return
	}
	defer resp.Body.Close()

	out, err := os.Create(LoaderFilePath)
	if err != nil {
		log.Printf("[ERROR] save loader: %v", err)
		return
	}

	_, copyErr := io.Copy(out, resp.Body)
	closeErr := out.Close()

	if copyErr != nil {
		log.Printf("[ERROR] write loader: %v", copyErr)
		return
	}
	if closeErr != nil {
		log.Printf("[ERROR] close loader: %v", closeErr)
		return
	}

	log.Printf("✅ Loader updated from Discord upload: %s (%d bytes)", exeAttachment.Filename, exeAttachment.Size)

	_, _ = s.ChannelMessageSend(m.ChannelID, "✅ Loader updated on server")

	addLogAndDiscord("SYSTEM", "LOADER_UPLOADED", "Discord", "",
		fmt.Sprintf("Loader replaced with %s (%d bytes)", exeAttachment.Filename, exeAttachment.Size))
}

// ---------- /redeem ----------

func cmdRedeem(s *discordgo.Session, i *discordgo.InteractionCreate) {
	licenseKey := normalizeLicenseKey(i.ApplicationCommandData().Options[0].StringValue())

	var userID, username string
	if i.Member != nil && i.Member.User != nil {
		userID = i.Member.User.ID
		username = i.Member.User.Username
	} else if i.User != nil {
		userID = i.User.ID
		username = i.User.Username
	} else {
		respondEphemeral(s, i, "❌ Could not determine your Discord identity.")
		return
	}

	if licenseKey == "" {
		respondEphemeral(s, i, "❌ You must provide a license key.")
		return
	}

	tx, err := db.Begin()
	if err != nil {
		respondEphemeral(s, i, "❌ Server error. Try again later.")
		return
	}
	defer func() { _ = tx.Rollback() }()

	var (
		id         int
		expiryDays sql.NullInt64
		expiryDate sql.NullTime
		activated  bool
		lifetime   bool
		discordID  sql.NullString
	)

	err = tx.QueryRow(`
		SELECT id, expiry_days, expiry_date, activated, COALESCE(lifetime,false), COALESCE(discord_id,'')
		FROM licenses WHERE lower(license_key) = lower($1)
		FOR UPDATE
	`, licenseKey).Scan(&id, &expiryDays, &expiryDate, &activated, &lifetime, &discordID)

	if err == sql.ErrNoRows {
		_ = tx.Rollback()
		addLogAndDiscord(licenseKey, "INVALID_KEY", "Discord-Redeem", "",
			fmt.Sprintf("Redeem attempt by %s (%s) — key not found", username, userID))
		respondEphemeral(s, i, "❌ Invalid license key.")
		return
	}
	if err != nil {
		log.Printf("[ERROR] redeem select: %v", err)
		respondEphemeral(s, i, "❌ Server error.")
		return
	}

	lifetimeKey := isLifetimeKey(lifetime, expiryDays)
	now := time.Now().UTC()
	if !lifetimeKey && expiryDate.Valid && now.After(expiryDate.Time) {
		_ = tx.Rollback()
		addLogAndDiscord(licenseKey, "EXPIRED", "Discord-Redeem", "",
			fmt.Sprintf("Redeem attempt by %s (%s) — expired", username, userID))
		respondEphemeral(s, i, "❌ This license has expired.")
		return
	}

	if discordID.Valid && discordID.String != "" && discordID.String != userID {
		_ = tx.Rollback()
		addLogAndDiscord(licenseKey, "HWID_MISMATCH", "Discord-Redeem", "",
			fmt.Sprintf("Redeem attempt by %s (%s) — already bound to %s", username, userID, discordID.String))
		respondEphemeral(s, i, "❌ This license is already linked to another Discord account.")
		return
	}

	finalExpiry := expiryDate
	if !activated {
		if !lifetimeKey {
			finalExpiry = sql.NullTime{Time: now.AddDate(0, 0, int(expiryDays.Int64)), Valid: true}
		}
		_, err = tx.Exec(`
			UPDATE licenses
			SET discord_id = $1, redeemed_at = $2, activated = TRUE,
			    activated_at = $2, expiry_date = $3, last_check = $2
			WHERE id = $4
		`, userID, now, finalExpiry, id)
	} else {
		_, err = tx.Exec(`
			UPDATE licenses SET discord_id = $1, redeemed_at = $2 WHERE id = $3
		`, userID, now, id)
	}
	if err != nil {
		log.Printf("[ERROR] redeem update: %v", err)
		respondEphemeral(s, i, "❌ Server error while saving.")
		return
	}

	if err = tx.Commit(); err != nil {
		log.Printf("[ERROR] redeem commit: %v", err)
		respondEphemeral(s, i, "❌ Server error.")
		return
	}

	addLogAndDiscord(licenseKey, "ACTIVATED", "Discord-Redeem", "",
		fmt.Sprintf("Redeemed by %s (%s)", username, userID))

	roleGranted := grantCustomerRole(s, i.GuildID, userID)

	expiryText := "Lifetime ♾️"
	if !lifetimeKey && finalExpiry.Valid {
		expiryText = finalExpiry.Time.Format("2006-01-02")
	}

	extra := ""
	if roleGranted {
		extra = "\n\n🎖️ You've been given the **Customer** role."
	}

	respondEphemeral(s, i, fmt.Sprintf(
		"✅ **License redeemed!**\n\nKey: `%s`\nExpires: **%s**%s\n\nYou can now use `/loader` to receive the loader in a private thread.",
		licenseKey, expiryText, extra,
	))
}

func grantCustomerRole(s *discordgo.Session, guildID, userID string) bool {
	roleID := DISCORD_CUSTOMER_ROLE_ID
	if guildID == "" || roleID == "" {
		return false
	}

	member, err := s.GuildMember(guildID, userID)
	if err != nil {
		log.Printf("[WARN] could not fetch member %s: %v", userID, err)
		return false
	}

	for _, r := range member.Roles {
		if r == roleID {
			return false
		}
	}

	if err := s.GuildMemberRoleAdd(guildID, userID, roleID); err != nil {
		log.Printf("[WARN] could not add role %s to %s: %v", roleID, userID, err)
		return false
	}
	log.Printf("✅ Granted role %s to %s", roleID, userID)
	return true
}

// ---------- /loader ----------

func cmdLoader(s *discordgo.Session, i *discordgo.InteractionCreate) {
	var userID, username string
	if i.Member != nil && i.Member.User != nil {
		userID = i.Member.User.ID
		username = i.Member.User.Username
	} else if i.User != nil {
		userID = i.User.ID
		username = i.User.Username
	} else {
		respondEphemeral(s, i, "❌ Could not determine your Discord identity.")
		return
	}

	var (
		licenseKey string
		expiryDate sql.NullTime
		expiryDays sql.NullInt64
		lifetime   bool
	)
	err := db.QueryRow(`
		SELECT license_key, expiry_date, expiry_days, COALESCE(lifetime,false)
		FROM licenses
		WHERE discord_id = $1
		ORDER BY id DESC LIMIT 1
	`, userID).Scan(&licenseKey, &expiryDate, &expiryDays, &lifetime)

	if err == sql.ErrNoRows {
		respondEphemeral(s, i, "❌ You don't have a license. Use `/redeem` first.")
		return
	}
	if err != nil {
		log.Printf("[ERROR] loader select: %v", err)
		respondEphemeral(s, i, "❌ Server error.")
		return
	}

	now := time.Now().UTC()
	if !isLifetimeKey(lifetime, expiryDays) && expiryDate.Valid && now.After(expiryDate.Time) {
		addLogAndDiscord(licenseKey, "EXPIRED", "Discord-Loader", "",
			fmt.Sprintf("Loader request by %s (%s) — expired", username, userID))
		respondEphemeral(s, i, "❌ Your license has expired.")
		return
	}

	stat, err := os.Stat(LoaderFilePath)
	if err != nil {
		log.Printf("[ERROR] stat loader: %v", err)
		respondEphemeral(s, i, fmt.Sprintf("❌ Loader file missing on server:\n```%v```", err))
		return
	}
	fileSize := stat.Size()

	if err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Flags: discordgo.MessageFlagsEphemeral},
	}); err != nil {
		log.Printf("[ERROR] defer loader: %v", err)
		return
	}

	threadName := fmt.Sprintf("loader-%s", username)
	if len(threadName) > 100 {
		threadName = threadName[:100]
	}

	thread, err := s.ThreadStartComplex(i.ChannelID, &discordgo.ThreadStart{
		Name:                threadName,
		Type:                discordgo.ChannelTypeGuildPrivateThread,
		Invitable:           false,
		AutoArchiveDuration: 60,
	})
	if err != nil {
		log.Printf("[ERROR] create thread: %v", err)
		_, _ = s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Could not create a private thread:\n```%v```", err),
			Flags:   discordgo.MessageFlagsEphemeral,
		})
		return
	}

	if err := s.ThreadMemberAdd(thread.ID, userID); err != nil {
		log.Printf("[WARN] could not add member %s to thread: %v", userID, err)
	}

	expiryText := "Lifetime ♾️"
	if !isLifetimeKey(lifetime, expiryDays) && expiryDate.Valid {
		expiryText = expiryDate.Time.Format("2006-01-02")
	}

	_, _ = s.ChannelMessageSend(
		thread.ID,
		fmt.Sprintf("<@%s>\n📥 **Your loader**\nLicense: `%s`\nExpires: **%s**\n\nDo not share this file. This thread will be deleted in **15 minutes**. Save the file to a permanent location.",
			userID, licenseKey, expiryText),
	)

	f, err := os.Open(LoaderFilePath)
	if err != nil {
		log.Printf("[ERROR] open loader: %v", err)
		_, _ = s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Could not open loader:\n```%v```", err),
			Flags:   discordgo.MessageFlagsEphemeral,
		})
		return
	}
	defer f.Close()

	_, err = s.ChannelFileSend(thread.ID, "loader.exe", f)
	if err != nil {
		log.Printf("[ERROR] upload loader to thread: %v", err)
		_, _ = s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Failed to upload the loader into the thread:\n```%v```", err),
			Flags:   discordgo.MessageFlagsEphemeral,
		})
		return
	}

	_, _ = s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
		Content: fmt.Sprintf("✅ Loader sent to your private thread: <#%s>\nDownload it now — the thread will be deleted in 15 minutes.", thread.ID),
		Flags:   discordgo.MessageFlagsEphemeral,
	})

	addLogAndDiscord(licenseKey, "VALIDATED", "Discord-Loader", "",
		fmt.Sprintf("Loader delivered to %s (%s) via private thread [%d bytes]", username, userID, fileSize))

	threadID := thread.ID
	channelID := i.ChannelID
	go func() {
		time.Sleep(threadCleanupDelay)

		_, _ = s.ChannelMessageSend(threadID, "⏳ This thread will be deleted in a few seconds.")

		if _, err := s.ChannelDelete(threadID); err != nil {
			log.Printf("[WARN] could not delete thread %s: %v", threadID, err)
			return
		}
		log.Printf("🗑️ Deleted loader thread %s in channel %s", threadID, channelID)
	}()
}

// ---------- /status ----------

func cmdStatus(s *discordgo.Session, i *discordgo.InteractionCreate) {
	var userID string
	if i.Member != nil && i.Member.User != nil {
		userID = i.Member.User.ID
	} else if i.User != nil {
		userID = i.User.ID
	} else {
		respondEphemeral(s, i, "❌ Could not determine your Discord identity.")
		return
	}

	var (
		licenseKey string
		activated  bool
		lifetime   bool
		expiryDate sql.NullTime
		expiryDays sql.NullInt64
		maxDevices int
		devicesRaw sql.NullString
		createdAt  sql.NullTime
	)

	err := db.QueryRow(`
		SELECT license_key, activated, COALESCE(lifetime,false),
		       expiry_date, expiry_days, max_devices, devices, created_at
		FROM licenses
		WHERE discord_id = $1
		ORDER BY id DESC LIMIT 1
	`, userID).Scan(&licenseKey, &activated, &lifetime, &expiryDate, &expiryDays, &maxDevices, &devicesRaw, &createdAt)

	if err == sql.ErrNoRows {
		respondEphemeral(s, i, "❌ You don't have a license bound to your Discord account.\nUse `/redeem` with a valid key first.")
		return
	}
	if err != nil {
		log.Printf("[ERROR] status select: %v", err)
		respondEphemeral(s, i, "❌ Server error.")
		return
	}

	now := time.Now().UTC()
	isLifetime := isLifetimeKey(lifetime, expiryDays)

	statusEmoji := "🔴"
	statusText := "INACTIVE"
	expiryText := "—"
	timeLeftText := "—"

	if isLifetime {
		statusEmoji = "🟢"
		statusText = "ACTIVE"
		expiryText = "Never (lifetime)"
		timeLeftText = "♾️ Lifetime"
	} else if expiryDate.Valid {
		if now.After(expiryDate.Time) {
			statusEmoji = "⚫"
			statusText = "EXPIRED"
			expiryText = expiryDate.Time.Format("2006-01-02 15:04 UTC")
			timeLeftText = "Expired"
		} else {
			if activated {
				statusEmoji = "🟢"
				statusText = "ACTIVE"
			}
			expiryText = expiryDate.Time.Format("2006-01-02 15:04 UTC")

			diff := expiryDate.Time.Sub(now)
			days := int(diff.Hours() / 24)
			hours := int(diff.Hours()) % 24
			minutes := int(diff.Minutes()) % 60

			if days > 0 {
				timeLeftText = fmt.Sprintf("%d days, %d hours", days, hours)
			} else if hours > 0 {
				timeLeftText = fmt.Sprintf("%d hours, %d minutes", hours, minutes)
			} else {
				timeLeftText = fmt.Sprintf("%d minutes", minutes)
			}
		}
	} else {
		statusEmoji = "🟢"
		statusText = "ACTIVE"
		expiryText = "Not set"
		timeLeftText = "—"
	}

	deviceCount := 0
	if devicesRaw.Valid && devicesRaw.String != "" && devicesRaw.String != "[]" {
		var list []string
		if err := json.Unmarshal([]byte(devicesRaw.String), &list); err == nil {
			deviceCount = len(list)
		}
	}

	deviceLimitText := fmt.Sprintf("%d", maxDevices)
	if maxDevices == 0 {
		deviceLimitText = "♾️ Unlimited"
	}

	createdText := "—"
	if createdAt.Valid {
		createdText = createdAt.Time.Format("2006-01-02")
	}

	msg := fmt.Sprintf(
		"**📊 Your License Status**\n\n"+
			"**Status:** %s %s\n"+
			"**License Key:** `%s`\n"+
			"**Redeemed on:** %s\n\n"+
			"**Expires:** %s\n"+
			"**Time left:** %s\n"+
			"**Devices:** %d / %s",
		statusEmoji, statusText,
		licenseKey,
		createdText,
		expiryText,
		timeLeftText,
		deviceCount, deviceLimitText,
	)

	respondEphemeral(s, i, msg)
}

func respondEphemeral(s *discordgo.Session, i *discordgo.InteractionCreate, msg string) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: msg,
			Flags:   discordgo.MessageFlagsEphemeral,
		},
	})
}