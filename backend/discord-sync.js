/*
  backend/discord-sync.js
  ========================
  SkyHigh Network — Discord Role Sync Backend
  Run this on your Oracle Cloud Ubuntu server (or adapt for Firebase Functions).

  SETUP:
  1. npm init -y
  2. npm install express node-fetch dotenv firebase-admin cors
  3. Create a .env file (see below)
  4. node discord-sync.js

  .env file contents:
  -------------------
  DISCORD_CLIENT_ID=your_discord_app_client_id
  DISCORD_CLIENT_SECRET=your_discord_app_client_secret
  DISCORD_BOT_TOKEN=your_bot_token
  DISCORD_GUILD_ID=your_server_id
  DISCORD_MEMBER_ROLE_ID=the_role_id_to_assign
  DISCORD_REDIRECT_URI=https://YOUR_DOMAIN/discord-callback.html
  STATE_SECRET=any_long_random_string_for_signing_state
  PORT=3001

  HOW IT WORKS:
  1. profile.html sends user to /discord/login?uid=FIREBASE_UID
  2. This server builds the Discord OAuth URL with a signed state, redirects user to Discord.
  3. Discord sends user back to /discord/callback?code=...&state=...
  4. This server:
     a. Validates state
     b. Exchanges code for Discord token
     c. Fetches Discord user
     d. Joins user to your guild (if guilds.join scope used)
     e. Applies the member role using the bot token
     f. Redirects to discord-callback.html?status=ok&discordUsername=...&discordId=...
        (The frontend page then writes the Discord data into Firestore)
*/

require('dotenv').config();
const express  = require('express');
const fetch    = require('node-fetch');
const cors     = require('cors');
const crypto   = require('crypto');

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,
  DISCORD_MEMBER_ROLE_ID,
  DISCORD_REDIRECT_URI,
  STATE_SECRET,
  PORT = 3001
} = process.env;

// ── Helpers ──────────────────────────────────────────────────────────

// Simple HMAC-signed state so we can verify it on return
function makeState(uid) {
  const payload = uid + ':' + Date.now();
  const sig = crypto.createHmac('sha256', STATE_SECRET).update(payload).digest('hex');
  return Buffer.from(payload + '.' + sig).toString('base64url');
}

function verifyState(state) {
  try {
    const decoded = Buffer.from(state, 'base64url').toString();
    const lastDot = decoded.lastIndexOf('.');
    const payload = decoded.slice(0, lastDot);
    const sig     = decoded.slice(lastDot + 1);
    const expected = crypto.createHmac('sha256', STATE_SECRET).update(payload).digest('hex');
    if (sig !== expected) return null;
    const uid = payload.split(':')[0];
    return uid || null;
  } catch {
    return null;
  }
}

async function discordFetch(path, options = {}) {
  const res = await fetch('https://discord.com/api/v10' + path, options);
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  if (!res.ok) {
    console.error('Discord API error', res.status, path, json);
    throw new Error('Discord API error ' + res.status + ': ' + (json.message || text));
  }
  return json;
}

// ── Routes ────────────────────────────────────────────────────────────

// Step 1: Build Discord OAuth URL
// Called by profile.html: /discord/login?uid=FIREBASE_UID
app.get('/discord/login', (req, res) => {
  const uid = req.query.uid;
  if (!uid) return res.status(400).send('Missing uid');

  const state = makeState(uid);
  const params = new URLSearchParams({
    client_id:     DISCORD_CLIENT_ID,
    response_type: 'code',
    redirect_uri:  DISCORD_REDIRECT_URI,
    scope:         'identify guilds.join',
    state,
    prompt:        'consent'
  });

  res.redirect('https://discord.com/oauth2/authorize?' + params.toString());
});

// Step 2: Discord OAuth callback
// Discord sends user back here with ?code=...&state=...
app.get('/discord/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect('/discord-callback.html?status=error&message=' + encodeURIComponent(error));
  }
  if (!code || !state) {
    return res.redirect('/discord-callback.html?status=error&message=Missing+code+or+state');
  }

  // Validate state and recover uid
  const uid = verifyState(state);
  if (!uid) {
    return res.redirect('/discord-callback.html?status=error&message=Invalid+state');
  }

  try {
    // Step 2a: Exchange code for Discord access token
    const tokenData = await discordFetch('/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  DISCORD_REDIRECT_URI
      })
    });

    const accessToken = tokenData.access_token;

    // Step 2b: Fetch Discord user identity
    const discordUser = await discordFetch('/users/@me', {
      headers: { Authorization: 'Bearer ' + accessToken }
    });

    const discordId       = discordUser.id;
    const discordUsername = discordUser.username;
    const discordAvatar   = discordUser.avatar || null;

    console.log('Discord user identified:', discordUsername, discordId, '→ Firebase uid:', uid);

    // Step 2c: Add user to the Discord guild (requires guilds.join scope)
    // Returns 201 if added, 204 if already in server — both are fine
    try {
      const joinRes = await fetch(
        'https://discord.com/api/v10/guilds/' + DISCORD_GUILD_ID + '/members/' + discordId,
        {
          method: 'PUT',
          headers: {
            Authorization: 'Bot ' + DISCORD_BOT_TOKEN,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ access_token: accessToken })
        }
      );
      if (joinRes.status === 201) console.log('User added to guild');
      else if (joinRes.status === 204) console.log('User already in guild');
      else {
        const t = await joinRes.text();
        console.warn('Join guild response:', joinRes.status, t);
      }
    } catch(joinErr) {
      console.warn('Could not add user to guild (non-fatal):', joinErr.message);
    }

    // Step 2d: Apply the SkyHigh Member role
    // Requires: bot has Manage Roles, bot role is above the target role
    const roleRes = await fetch(
      'https://discord.com/api/v10/guilds/' + DISCORD_GUILD_ID +
      '/members/' + discordId + '/roles/' + DISCORD_MEMBER_ROLE_ID,
      {
        method: 'PUT',
        headers: { Authorization: 'Bot ' + DISCORD_BOT_TOKEN }
      }
    );

    if (roleRes.status === 204) {
      console.log('Role applied to', discordUsername);
    } else {
      const t = await roleRes.text();
      console.error('Failed to apply role:', roleRes.status, t);
      // Non-fatal: redirect with ok so Firestore still gets the link
      // discordRoleSynced will stay false and can be retried
    }

    const roleSynced = roleRes.status === 204;

    /*
      NOTE: The Firestore write happens in discord-callback.html on the frontend.
      We just pass the Discord data in the redirect URL here.
      If you prefer to write Firestore server-side instead, install firebase-admin,
      initialise it with your service account, and do:

        const admin = require('firebase-admin');
        admin.firestore().doc('joinApplications/' + uid).set({
          discordLinked: true, discordUserId: discordId,
          discordUsername, discordAvatar,
          discordRoleSynced: roleSynced
        }, { merge: true });

      Then redirect to /discord-callback.html?status=ok without the extra params.
    */

    const redirectParams = new URLSearchParams({
      status:          'ok',
      uid,
      discordId,
      discordUsername,
      discordAvatar:   discordAvatar || '',
      roleSynced:      roleSynced ? '1' : '0'
    });

    res.redirect('/discord-callback.html?' + redirectParams.toString());

  } catch(err) {
    console.error('OAuth callback error:', err);
    res.redirect('/discord-callback.html?status=error&message=' + encodeURIComponent(err.message));
  }
});

// Step 3: Optional manual re-sync endpoint (call from staff dashboard etc.)
// POST /discord/sync-role  { uid, discordUserId }
app.post('/discord/sync-role', async (req, res) => {
  const { uid, discordUserId } = req.body;
  if (!uid || !discordUserId) return res.status(400).json({ error: 'Missing uid or discordUserId' });

  try {
    const roleRes = await fetch(
      'https://discord.com/api/v10/guilds/' + DISCORD_GUILD_ID +
      '/members/' + discordUserId + '/roles/' + DISCORD_MEMBER_ROLE_ID,
      {
        method: 'PUT',
        headers: { Authorization: 'Bot ' + DISCORD_BOT_TOKEN }
      }
    );
    if (roleRes.status === 204) {
      res.json({ ok: true, message: 'Role applied' });
    } else {
      const t = await roleRes.text();
      res.status(400).json({ error: 'Discord returned ' + roleRes.status, detail: t });
    }
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log('SkyHigh Discord sync running on port', PORT));
