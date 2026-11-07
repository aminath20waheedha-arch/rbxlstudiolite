const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const rbxl = require('./rbxl');
const db = require('./db');

const scrypt = promisify(crypto.scrypt);
const PORT = process.env.PORT || 3000;
const MAX_BODY = 250 * 1024 * 1024;
const TTL = 60 * 60 * 1000;
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;
const PUBLIC_URL = (process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || '').replace(/\/$/, '');
const RBX_ID = process.env.ROBLOX_CLIENT_ID, RBX_SECRET = process.env.ROBLOX_CLIENT_SECRET;
const HAS_SECRET = !!process.env.KEY_SECRET && process.env.KEY_SECRET.length >= 16;
const ACCOUNTS = !!db && HAS_SECRET;
const ROBLOX = ACCOUNTS && !!RBX_ID && !!RBX_SECRET && !!PUBLIC_URL;

const sessions = new Map();      // uploaded place models
const oauthStates = new Map();   // state -> {userId, verifier, exp}
const attempts = new Map();      // ip -> [timestamps]

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of sessions) if (now - v.created > TTL) sessions.delete(k);
  for (const [k, v] of oauthStates) if (v.exp < now) oauthStates.delete(k);
}, 60 * 1000).unref();

// ---------- helpers ----------
const fail = (msg, code = 400) => Object.assign(new Error(msg), { status: code });
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { reject(new Error('File too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req) { try { return JSON.parse((await readBody(req)).toString('utf8') || '{}'); } catch { throw fail('Bad request'); } }
function json(res, code, obj, headers = {}) { res.writeHead(code, { 'Content-Type': 'application/json', ...headers }); res.end(JSON.stringify(obj)); }
function cookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return out;
}
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function cookieHeader(req, token, maxAge) {
  const secure = (req.headers['x-forwarded-proto'] || '').includes('https') ? '; Secure' : '';
  return `sid=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}
function throttle(req, limit = 10, windowMs = 10 * 60 * 1000) {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const now = Date.now();
  const list = (attempts.get(ip) || []).filter(t => now - t < windowMs);
  if (list.length >= limit) throw fail('Too many attempts. Try again in a few minutes.', 429);
  list.push(now); attempts.set(ip, list);
}

// encryption of API keys / OAuth tokens at rest (AES-256-GCM, key from KEY_SECRET)
const encKey = () => crypto.createHash('sha256').update(process.env.KEY_SECRET).digest();
function enc(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', encKey(), iv);
  const ct = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), ct].map(b => b.toString('base64')).join('.');
}
function dec(s) {
  const [iv, tag, ct] = s.split('.').map(x => Buffer.from(x, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', encKey(), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + (await scrypt(pw, salt, 64)).toString('hex');
}
async function checkPassword(pw, stored) {
  const [s, h] = stored.split(':');
  const got = await scrypt(pw, Buffer.from(s, 'hex'), 64);
  return crypto.timingSafeEqual(got, Buffer.from(h, 'hex'));
}

async function currentUser(req) {
  if (!ACCOUNTS) return null;
  const sid = cookies(req).sid;
  if (!sid) return null;
  const s = await db.getSession(sha(sid));
  if (!s || s.expires < Date.now()) return null;
  const u = await db.getUserById(s.userId);
  return u ? { id: u.id, username: u.username } : null;
}
async function startSession(req, res, user, status = 200, extra = {}) {
  const token = crypto.randomBytes(32).toString('hex');
  await db.createSession(sha(token), user.id, Date.now() + SESSION_MS);
  json(res, status, { ok: true, user: { username: user.username }, ...extra }, { 'Set-Cookie': cookieHeader(req, token, SESSION_MS / 1000) });
}
function needUser(user) { if (!user) throw fail('Please log in first.', 401); return user; }
function getModel(url) {
  const m = sessions.get(url.searchParams.get('session'));
  if (!m || Date.now() - m.created > TTL) throw fail('Session expired. Please re-open your place.', 410);
  return m;
}

// ---------- Roblox OAuth ----------
const redirectUri = () => PUBLIC_URL + '/auth/roblox/callback';
async function rbxToken(params) {
  const r = await fetch('https://apis.roblox.com/oauth/v1/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: RBX_ID, client_secret: RBX_SECRET, ...params })
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw fail('Roblox login failed: ' + (d.error_description || d.error || r.status), 502);
  return d;
}
async function accessToken(userId) {
  const link = await db.getLink(userId);
  if (!link) throw fail('Connect your Roblox account first.', 400);
  if (link.expires > Date.now() + 60000) return dec(link.access_enc);
  const d = await rbxToken({ grant_type: 'refresh_token', refresh_token: dec(link.refresh_enc) }).catch(async e => {
    await db.deleteLink(userId); throw fail('Roblox connection expired. Please connect again.', 401);
  });
  await db.setLink(userId, { roblox_id: link.roblox_id, roblox_name: link.roblox_name, access_enc: enc(d.access_token),
    refresh_enc: enc(d.refresh_token || dec(link.refresh_enc)), expires: Date.now() + (d.expires_in || 900) * 1000 });
  return d.access_token;
}
async function listGames(userId) {
  const token = await accessToken(userId);
  const r = await fetch('https://apis.roblox.com/oauth/v1/token/resources', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token, client_id: RBX_ID, client_secret: RBX_SECRET })
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw fail('Could not read your games from Roblox.', 502);
  const ids = new Set();
  for (const info of d.resource_infos || []) for (const id of (info.resources?.universe?.ids || [])) ids.add(String(id));
  const list = [...ids];
  const games = new Map();
  for (let i = 0; i < list.length; i += 50) {
    const chunk = list.slice(i, i + 50);
    try {
      const g = await fetch('https://games.roblox.com/v1/games?universeIds=' + chunk.join(',')).then(x => x.json());
      for (const x of g.data || []) games.set(String(x.id), { name: x.name, placeId: String(x.rootPlaceId || '') });
    } catch {}
  }
  return list.map(id => ({ universeId: id, name: games.get(id)?.name || 'Experience ' + id, placeId: games.get(id)?.placeId || '' }));
}

// ---------- publishing ----------
async function publish(model, user, b) {
  let headers, universeId, placeId, manual = false;
  if (b.profileId) {
    needUser(user);
    const p = await db.getProfile(user.id, +b.profileId);
    if (!p) throw fail('Saved target not found.', 404);
    headers = { 'x-api-key': dec(p.enc) }; universeId = p.universe_id; placeId = p.place_id;
  } else if (b.useRoblox) {
    needUser(user);
    headers = { Authorization: 'Bearer ' + await accessToken(user.id) }; universeId = b.universeId; placeId = b.placeId;
  } else {
    headers = { 'x-api-key': (b.apiKey || '').trim() }; universeId = b.universeId; placeId = b.placeId; manual = true;
    if (!headers['x-api-key']) throw fail('Enter your API key.');
  }
  universeId = String(universeId || '').trim(); placeId = String(placeId || '').trim();
  if (!/^\d+$/.test(universeId) || !/^\d+$/.test(placeId)) throw fail('Universe ID and Place ID must be numbers.');
  const vt = b.versionType === 'Published' ? 'Published' : 'Saved';
  const r = await fetch(`https://apis.roblox.com/universes/v1/${universeId}/places/${placeId}/versions?versionType=${vt}`, {
    method: 'POST', headers: { ...headers, 'Content-Type': 'application/octet-stream' }, body: rbxl.build(model)
  });
  const text = await r.text();
  if (!r.ok) throw fail(`Roblox returned ${r.status}: ${text}`, r.status === 401 || r.status === 403 ? 400 : r.status);
  let saved = false;
  if (manual && b.save && user && ACCOUNTS) {
    const existing = await db.listProfiles(user.id);
    if (existing.length < 20) {
      await db.addProfile(user.id, { label: String(b.label || 'My game').slice(0, 40), universe_id: universeId, place_id: placeId, enc: enc(headers['x-api-key']) });
      saved = true;
    }
  }
  return { ok: true, response: text, saved };
}

// ---------- routes ----------
async function route(req, res, url) {
  const p = url.pathname, m = req.method;
  if (m === 'GET' && (p === '/' || p === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
  }
  if (p === '/health') return json(res, 200, { ok: true });
  if (p === '/api/config') return json(res, 200, { accounts: ACCOUNTS, roblox: ROBLOX });

  if (m === 'GET' && p === '/auth/roblox/callback') {
    try {
      if (!ROBLOX) throw fail('Roblox login is not set up.');
      const user = needUser(await currentUser(req));
      const st = oauthStates.get(url.searchParams.get('state'));
      oauthStates.delete(url.searchParams.get('state'));
      if (!st || st.exp < Date.now() || st.userId !== user.id) throw fail('Login expired. Try again.');
      if (url.searchParams.get('error')) throw fail('Roblox login was cancelled.');
      const d = await rbxToken({ grant_type: 'authorization_code', code: url.searchParams.get('code'), redirect_uri: redirectUri(), code_verifier: st.verifier });
      const info = await fetch('https://apis.roblox.com/oauth/v1/userinfo', { headers: { Authorization: 'Bearer ' + d.access_token } }).then(r => r.json()).catch(() => ({}));
      await db.setLink(user.id, { roblox_id: String(info.sub || ''), roblox_name: info.preferred_username || info.name || 'Roblox user',
        access_enc: enc(d.access_token), refresh_enc: enc(d.refresh_token), expires: Date.now() + (d.expires_in || 900) * 1000 });
      res.writeHead(302, { Location: '/?linked=1' }); return res.end();
    } catch (e) {
      res.writeHead(302, { Location: '/?linkerror=' + encodeURIComponent(e.message) }); return res.end();
    }
  }
  if (m === 'GET' && p === '/auth/roblox/start') {
    try {
      if (!ROBLOX) throw fail('Roblox login is not set up.');
      const user = needUser(await currentUser(req));
      const state = crypto.randomBytes(16).toString('hex');
      const verifier = crypto.randomBytes(32).toString('base64url');
      oauthStates.set(state, { userId: user.id, verifier, exp: Date.now() + 10 * 60 * 1000 });
      const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
      const q = new URLSearchParams({ client_id: RBX_ID, redirect_uri: redirectUri(), scope: process.env.ROBLOX_SCOPES || 'openid profile universe-places:write',
        response_type: 'code', state, code_challenge: challenge, code_challenge_method: 'S256' });
      res.writeHead(302, { Location: 'https://apis.roblox.com/oauth/v1/authorize?' + q }); return res.end();
    } catch (e) { res.writeHead(302, { Location: '/?linkerror=' + encodeURIComponent(e.message) }); return res.end(); }
  }

  if (!p.startsWith('/api/')) throw fail('Not found', 404);
  if (m !== 'GET' && req.headers['x-csrf'] !== '1') throw fail('Bad request', 403);

  // --- place editing (guests allowed) ---
  if (m === 'POST' && p === '/api/upload') {
    const model = rbxl.parse(await readBody(req));
    const id = crypto.randomBytes(12).toString('hex');
    model.created = Date.now();
    model.filename = decodeURIComponent(req.headers['x-filename'] || 'place.rbxl');
    sessions.set(id, model);
    return json(res, 200, { session: id, filename: model.filename,
      scripts: model.scripts.map(s => ({ id: s.id, name: s.name, className: s.className, path: s.path, length: rbxl.sourceLength(model, s.id) })) });
  }
  if (m === 'GET' && p === '/api/session') {
    const model = getModel(url);
    return json(res, 200, { session: url.searchParams.get('session'), filename: model.filename, edited: [...(model.edited || [])],
      scripts: model.scripts.map(s => ({ id: s.id, name: s.name, className: s.className, path: s.path, length: rbxl.sourceLength(model, s.id) })) });
  }
  if (m === 'GET' && p === '/api/script') {
    const model = getModel(url), id = +url.searchParams.get('id');
    if (!model.scripts[id]) throw fail('No such script', 404);
    return json(res, 200, { source: rbxl.getSource(model, id) });
  }
  if (m === 'POST' && p === '/api/script') {
    const model = getModel(url), id = +url.searchParams.get('id');
    if (!model.scripts[id]) throw fail('No such script', 404);
    const body = (await readBody(req)).toString('utf8');
    rbxl.setSource(model, id, body);
    (model.edited ||= new Set()).add(id);
    return json(res, 200, { ok: true, length: body.length });
  }
  if (m === 'GET' && p === '/api/download') {
    const model = getModel(url), out = rbxl.build(model);
    const name = model.filename.replace(/\.rbxl$/i, '') + '-edited.rbxl';
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': out.length, 'Content-Disposition': `attachment; filename="${encodeURIComponent(name)}"` });
    return res.end(out);
  }
  if (m === 'POST' && p === '/api/publish') {
    const model = getModel(url);
    return json(res, 200, await publish(model, await currentUser(req), await readJson(req)));
  }

  // --- accounts ---
  if (!ACCOUNTS) throw fail('Accounts are not enabled on this server.', 503);
  if (m === 'POST' && (p === '/api/signup' || p === '/api/login')) {
    throttle(req);
    const { username, password } = await readJson(req);
    const name = String(username || '').trim().toLowerCase();
    if (p === '/api/signup') {
      if (!/^[a-z0-9_]{3,20}$/.test(name)) throw fail('Username: 3-20 letters, numbers or underscores.');
      if (typeof password !== 'string' || password.length < 8 || password.length > 200) throw fail('Password must be at least 8 characters.');
      try { return startSession(req, res, await db.createUser(name, await hashPassword(password)), 201); }
      catch (e) { if (e.code === 'EXISTS') throw fail('That username is taken.', 409); throw e; }
    }
    const u = await db.getUserByName(name);
    if (!u || typeof password !== 'string' || !(await checkPassword(password, u.pass))) throw fail('Wrong username or password.', 401);
    return startSession(req, res, u);
  }
  if (m === 'POST' && p === '/api/logout') {
    const sid = cookies(req).sid; if (sid) await db.deleteSession(sha(sid));
    return json(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader(req, '', 0) });
  }
  if (m === 'GET' && p === '/api/me') {
    const user = await currentUser(req);
    if (!user) return json(res, 200, { user: null });
    const profiles = (await db.listProfiles(user.id)).map(x => ({ id: x.id, label: x.label, universeId: x.universe_id, placeId: x.place_id }));
    const link = await db.getLink(user.id);
    return json(res, 200, { user, profiles, roblox: link ? { name: link.roblox_name } : null });
  }
  if (m === 'DELETE' && p === '/api/profiles') {
    const user = needUser(await currentUser(req));
    await db.deleteProfile(user.id, +url.searchParams.get('id'));
    return json(res, 200, { ok: true });
  }
  if (m === 'GET' && p === '/api/roblox/games') {
    const user = needUser(await currentUser(req));
    return json(res, 200, { games: await listGames(user.id) });
  }
  if (m === 'POST' && p === '/api/roblox/unlink') {
    const user = needUser(await currentUser(req));
    await db.deleteLink(user.id);
    return json(res, 200, { ok: true });
  }
  throw fail('Not found', 404);
}

const server = http.createServer(async (req, res) => {
  try { await route(req, res, new URL(req.url, 'http://x')); }
  catch (e) { if (!res.headersSent) json(res, e.status || 500, { error: e.message }); else res.end(); }
});
db ? db.init().then(() => server.listen(PORT, () => console.log('Listening on ' + PORT + (ACCOUNTS ? ' (accounts on' + (ROBLOX ? ', Roblox login on)' : ')') : ''))))
   : server.listen(PORT, () => console.log('Listening on ' + PORT + ' (accounts off)'));
