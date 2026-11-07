// Data layer. DATABASE_URL=<postgres url> for real use, DATABASE_URL=memory for local testing,
// unset = accounts disabled (the site still works for guests).
const url = process.env.DATABASE_URL;

function memoryDb() {
  const users = new Map(), sessions = new Map(), profiles = new Map(), links = new Map();
  let uid = 1, pid = 1;
  return {
    async init() {},
    async createUser(username, pass) {
      for (const u of users.values()) if (u.username === username) throw Object.assign(new Error('exists'), { code: 'EXISTS' });
      const u = { id: uid++, username, pass }; users.set(u.id, u); return { id: u.id, username };
    },
    async getUserByName(n) { for (const u of users.values()) if (u.username === n) return u; return null; },
    async getUserById(id) { return users.get(id) || null; },
    async createSession(h, userId, expires) { sessions.set(h, { userId, expires }); },
    async getSession(h) { return sessions.get(h) || null; },
    async deleteSession(h) { sessions.delete(h); },
    async listProfiles(userId) { return [...profiles.values()].filter(p => p.user_id === userId); },
    async addProfile(userId, p) { const row = { id: pid++, user_id: userId, ...p }; profiles.set(row.id, row); return row; },
    async getProfile(userId, id) { const p = profiles.get(id); return p && p.user_id === userId ? p : null; },
    async deleteProfile(userId, id) { const p = profiles.get(id); if (p && p.user_id === userId) profiles.delete(id); },
    async getLink(userId) { return links.get(userId) || null; },
    async setLink(userId, l) { links.set(userId, { user_id: userId, ...l }); },
    async deleteLink(userId) { links.delete(userId); }
  };
}

function pgDb() {
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: url, ssl: process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false } });
  const q = (s, p) => pool.query(s, p).then(r => r.rows);
  return {
    async init() {
      await q(`CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass TEXT NOT NULL, created TIMESTAMPTZ DEFAULT now())`);
      await q(`CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, expires BIGINT)`);
      await q(`CREATE TABLE IF NOT EXISTS profiles(id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, label TEXT, universe_id TEXT, place_id TEXT, enc TEXT)`);
      await q(`CREATE TABLE IF NOT EXISTS links(user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, roblox_id TEXT, roblox_name TEXT, access_enc TEXT, refresh_enc TEXT, expires BIGINT)`);
    },
    async createUser(username, pass) {
      try { return (await q('INSERT INTO users(username,pass) VALUES($1,$2) RETURNING id,username', [username, pass]))[0]; }
      catch (e) { if (e.code === '23505') throw Object.assign(new Error('exists'), { code: 'EXISTS' }); throw e; }
    },
    async getUserByName(n) { return (await q('SELECT * FROM users WHERE username=$1', [n]))[0] || null; },
    async getUserById(id) { return (await q('SELECT * FROM users WHERE id=$1', [id]))[0] || null; },
    async createSession(h, userId, expires) { await q('INSERT INTO sessions VALUES($1,$2,$3)', [h, userId, expires]); await q('DELETE FROM sessions WHERE expires<$1', [Date.now()]); },
    async getSession(h) { const r = (await q('SELECT user_id,expires FROM sessions WHERE token_hash=$1', [h]))[0]; return r ? { userId: r.user_id, expires: +r.expires } : null; },
    async deleteSession(h) { await q('DELETE FROM sessions WHERE token_hash=$1', [h]); },
    async listProfiles(userId) { return q('SELECT * FROM profiles WHERE user_id=$1 ORDER BY id', [userId]); },
    async addProfile(userId, p) { return (await q('INSERT INTO profiles(user_id,label,universe_id,place_id,enc) VALUES($1,$2,$3,$4,$5) RETURNING *', [userId, p.label, p.universe_id, p.place_id, p.enc]))[0]; },
    async getProfile(userId, id) { return (await q('SELECT * FROM profiles WHERE id=$1 AND user_id=$2', [id, userId]))[0] || null; },
    async deleteProfile(userId, id) { await q('DELETE FROM profiles WHERE id=$1 AND user_id=$2', [id, userId]); },
    async getLink(userId) { const r = (await q('SELECT * FROM links WHERE user_id=$1', [userId]))[0]; return r ? { ...r, expires: +r.expires } : null; },
    async setLink(userId, l) {
      await q(`INSERT INTO links VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (user_id) DO UPDATE SET roblox_id=$2,roblox_name=$3,access_enc=$4,refresh_enc=$5,expires=$6`,
        [userId, l.roblox_id, l.roblox_name, l.access_enc, l.refresh_enc, l.expires]);
    },
    async deleteLink(userId) { await q('DELETE FROM links WHERE user_id=$1', [userId]); }
  };
}

module.exports = !url ? null : url === 'memory' ? memoryDb() : pgDb();
