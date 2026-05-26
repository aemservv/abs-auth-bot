const fs = require('fs');
const path = require('path');
const express = require('express');
const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, ModalBuilder, TextInputBuilder, TextInputStyle, ActionRowBuilder } = require('discord.js');

const config = {
    token: process.env.TOKEN || require('./config.json').token,
    adminId: process.env.ADMIN_ID || require('./config.json').adminId,
    port: parseInt(process.env.PORT || require('./config.json').port),
};
const DATA_FILE = path.join(__dirname, 'licenses.json');

// === Data layer ===
let licenses = {};
let systemEnabled = true;

function loadData() {
    try {
        if (fs.existsSync(DATA_FILE)) {
            const raw = fs.readFileSync(DATA_FILE, 'utf-8');
            const data = JSON.parse(raw);
            licenses = data.licenses || {};
            systemEnabled = data.systemEnabled !== undefined ? data.systemEnabled : true;
        }
    } catch (e) { console.error('Load error:', e); }
}

function saveData() {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify({ licenses, systemEnabled }, null, 2));
    } catch (e) { console.error('Save error:', e); }
}

function generateKey() {
    const rand = () => Math.random().toString(36).substring(2, 10).toUpperCase();
    return `${rand()}-${rand()}-${rand()}`;
}

loadData();

// === Express HTTP server (for Go client) ===
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.post('/verify', (req, res) => {
    const key = (req.body.key || '').trim();
    const hwid = (req.body.hwid || '').trim();

    if (!systemEnabled) {
        return res.json({ status: 'invalid', message: 'Auth system is currently disabled' });
    }
    if (!key) return res.json({ status: 'invalid', message: 'No key provided' });
    if (!hwid) return res.json({ status: 'invalid', message: 'No HWID provided' });

    const lic = licenses[key];
    if (!lic) return res.json({ status: 'invalid', message: 'License key not found' });

    if (!lic.active) return res.json({ status: 'invalid', message: 'License has been deactivated' });

    if (lic.expiresAt && Date.parse(lic.expiresAt) < Date.now()) {
        lic.active = false;
        saveData();
        return res.json({ status: 'invalid', message: 'License expired' });
    }

    // First activation — bind HWID
    if (!lic.hwid) {
        lic.hwid = hwid;
        lic.lastSeen = new Date().toISOString();
        lic.lastIP = req.ip;
        saveData();
        return res.json({ status: 'valid', plan: lic.plan, hwid: hwid, expiresAt: lic.expiresAt || null });
    }

    if (lic.hwid !== hwid) {
        return res.json({ status: 'invalid', message: 'HWID mismatch — key is bound to another machine' });
    }

    lic.lastSeen = new Date().toISOString();
    lic.lastIP = req.ip;
    saveData();

    res.json({ status: 'valid', plan: lic.plan, hwid: lic.hwid, expiresAt: lic.expiresAt || null });
});

app.get('/', (req, res) => {
    res.json({ status: 'ok', systemEnabled, licenseCount: Object.keys(licenses).length });
});

app.listen(config.port, () => {
    console.log(`HTTP server on port ${config.port}`);
});

// === Discord bot ===
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.once('ready', async () => {
    console.log(`Bot logged in as ${client.user.tag}`);

    const commands = [
        new SlashCommandBuilder()
            .setName('toggle')
            .setDescription('Turn the auth system on/off (admin only)'),
        new SlashCommandBuilder()
            .setName('generate')
            .setDescription('Generate a new license key (opens a form)'),
        new SlashCommandBuilder()
            .setName('deactivate')
            .setDescription('Deactivate a license key (admin only)')
            .addStringOption(opt => opt.setName('key').setDescription('The license key').setRequired(true)),
        new SlashCommandBuilder()
            .setName('list')
            .setDescription('List all license keys (admin only)'),
        new SlashCommandBuilder()
            .setName('hwid')
            .setDescription('Get HWID bound to a key')
            .addStringOption(opt => opt.setName('key').setDescription('The license key').setRequired(true)),
        new SlashCommandBuilder()
            .setName('status')
            .setDescription('Show current system status'),
    ];

    const rest = new REST({ version: '10' }).setToken(config.token);
    try {
        await rest.put(Routes.applicationCommands(client.user.id), { body: commands });
        console.log('Slash commands registered');
    } catch (e) {
        console.error('Failed to register commands:', e);
    }
});

client.on('interactionCreate', async interaction => {
    if (interaction.isModalSubmit() && interaction.customId === 'generateModal') {
        const hwid = interaction.fields.getTextInputValue('hwid') || '';
        const days = parseInt(interaction.fields.getTextInputValue('days')) || 0;
        const plan = interaction.fields.getTextInputValue('plan') || 'lifetime';

        const key = generateKey();
        const expiresAt = days > 0 ? new Date(Date.now() + days * 86400000).toISOString() : null;

        licenses[key] = {
            hwid,
            plan,
            issuedAt: new Date().toISOString(),
            expiresAt,
            active: true,
            lastIP: '',
            lastSeen: null,
        };
        saveData();

        let msg = `✅ **Key generated**\n\`${key}\`\nPlan: ${plan}\n`;
        msg += hwid ? `HWID: \`${hwid}\`` : 'HWID: (first activation)';
        if (expiresAt) msg += `\nExpires: ${expiresAt}`;
        if (days > 0) msg += `\nDays: ${days}`;
        return interaction.reply({ content: msg, ephemeral: true });
    }

    if (!interaction.isChatInputCommand()) return;

    const isAdmin = interaction.user.id === config.adminId;

    switch (interaction.commandName) {
        case 'toggle': {
            if (!isAdmin) return interaction.reply({ content: '❌ Admin only.', ephemeral: true });
            systemEnabled = !systemEnabled;
            saveData();
            const status = systemEnabled ? '🟢 **Enabled**' : '🔴 **Disabled**';
            return interaction.reply(`Auth system is now ${status}`);
        }

        case 'generate': {
            if (!isAdmin) return interaction.reply({ content: '❌ Admin only.', ephemeral: true });

            const modal = new ModalBuilder()
                .setCustomId('generateModal')
                .setTitle('Generate License Key');

            const hwidInput = new TextInputBuilder()
                .setCustomId('hwid')
                .setLabel('HWID (leave empty for first-activation)')
                .setStyle(TextInputStyle.Short)
                .setRequired(false);

            const daysInput = new TextInputBuilder()
                .setCustomId('days')
                .setLabel('Days (0 = never expires)')
                .setStyle(TextInputStyle.Short)
                .setValue('0')
                .setRequired(true);

            const planInput = new TextInputBuilder()
                .setCustomId('plan')
                .setLabel('Plan name')
                .setStyle(TextInputStyle.Short)
                .setValue('lifetime')
                .setRequired(true);

            const row1 = new ActionRowBuilder().addComponents(hwidInput);
            const row2 = new ActionRowBuilder().addComponents(daysInput);
            const row3 = new ActionRowBuilder().addComponents(planInput);
            modal.addComponents(row1, row2, row3);

            return interaction.showModal(modal);
        }

        case 'deactivate': {
            if (!isAdmin) return interaction.reply({ content: '❌ Admin only.', ephemeral: true });
            const key = interaction.options.getString('key');
            if (!licenses[key]) return interaction.reply({ content: '❌ Key not found.', ephemeral: true });
            licenses[key].active = false;
            saveData();
            return interaction.reply({ content: `🔴 Key \`${key}\` deactivated.`, ephemeral: true });
        }

        case 'list': {
            if (!isAdmin) return interaction.reply({ content: '❌ Admin only.', ephemeral: true });
            const keys = Object.keys(licenses);
            if (keys.length === 0) return interaction.reply({ content: 'No licenses stored.', ephemeral: true });

            const chunks = [];
            let chunk = '**Licenses:**\n';
            for (const key of keys) {
                const l = licenses[key];
                const line = `\`${key}\` ${l.active ? '🟢' : '🔴'} ${l.plan} HWID:${l.hwid ? '`'+l.hwid.substring(0,16)+'...`' : '—'}\n`;
                if (chunk.length + line.length > 1900) {
                    chunks.push(chunk);
                    chunk = '';
                }
                chunk += line;
            }
            if (chunk) chunks.push(chunk);
            for (const c of chunks) await interaction.user.send(c);
            return interaction.reply({ content: `📨 Sent ${chunks.length} message(s) in DM.`, ephemeral: true });
        }

        case 'hwid': {
            const key = interaction.options.getString('key');
            const lic = licenses[key];
            if (!lic) return interaction.reply({ content: '❌ Key not found.', ephemeral: true });
            const hwid = lic.hwid || 'Not yet bound (first activation)';
            return interaction.reply({ content: `Key \`${key}\`\nHWID: \`${hwid}\``, ephemeral: true });
        }

        case 'status': {
            const count = Object.keys(licenses).length;
            const active = Object.values(licenses).filter(l => l.active).length;
            const sysStatus = systemEnabled ? '🟢 Enabled' : '🔴 Disabled';
            return interaction.reply({
                content: `**System:** ${sysStatus}\n**Licenses:** ${count} total, ${active} active`,
                ephemeral: true,
            });
        }
    }
});

client.login(config.token).catch(e => {
    console.error('Failed to login:', e);
    process.exit(1);
});
