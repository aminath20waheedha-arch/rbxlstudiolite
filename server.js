const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const rbxl = require('./rbxl');

const PORT = process.env.PORT || 3000;
const MAX_BODY = 250 * 1024 * 1024;
const TTL = 60 * 60 * 1000;
const sessions = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of sessions) if (now - v.created > TTL) sessions.delete(k);
}, 60 * 1000).unref();

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { reject(new Error('File too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function json(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(b);
}
function getSession(url) {
  const s = sessions.get(url.searchParams.get('session'));
  if (!s || Date.now() - s.created > TTL) return null;
  return s;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
    }
    if (url.pathname === '/health') return json(res, 200, { ok: true });

    if (req.method === 'POST' && url.pathname === '/api/upload') {
      const buf = await readBody(req);
      const model = rbxl.parse(buf);
      const id = crypto.randomBytes(12).toString('hex');
      model.created = Date.now();
      model.filename = decodeURIComponent(req.headers['x-filename'] || 'place.rbxl');
      sessions.set(id, model);
      return json(res, 200, {
        session: id,
        filename: model.filename,
        scripts: model.scripts.map(s => ({ id: s.id, name: s.name, className: s.className, path: s.path, length: rbxl.sourceLength(model, s.id) }))
      });
    }

    if (url.pathname.startsWith('/api/')) {
      const model = getSession(url);
      if (!model) return json(res, 410, { error: 'Session expired. Please re-open your place.' });

      if (req.method === 'GET' && url.pathname === '/api/script') {
        const id = +url.searchParams.get('id');
        if (!model.scripts[id]) return json(res, 404, { error: 'No such script' });
        return json(res, 200, { source: rbxl.getSource(model, id) });
      }
      if (req.method === 'POST' && url.pathname === '/api/script') {
        const id = +url.searchParams.get('id');
        if (!model.scripts[id]) return json(res, 404, { error: 'No such script' });
        const body = (await readBody(req)).toString('utf8');
        rbxl.setSource(model, id, body);
        return json(res, 200, { ok: true, length: body.length });
      }
      if (req.method === 'GET' && url.pathname === '/api/download') {
        const out = rbxl.build(model);
        const name = model.filename.replace(/\.rbxl$/i, '') + '-edited.rbxl';
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Length': out.length,
          'Content-Disposition': `attachment; filename="${encodeURIComponent(name)}"`
        });
        return res.end(out);
      }
      if (req.method === 'POST' && url.pathname === '/api/publish') {
        const { apiKey, universeId, placeId, versionType } = JSON.parse((await readBody(req)).toString('utf8'));
        if (!apiKey || !/^\d+$/.test(universeId || '') || !/^\d+$/.test(placeId || '')) {
          return json(res, 400, { error: 'API key, Universe ID and Place ID (numbers) are required.' });
        }
        const vt = versionType === 'Published' ? 'Published' : 'Saved';
        const out = rbxl.build(model);
        const r = await fetch(`https://apis.roblox.com/universes/v1/${universeId}/places/${placeId}/versions?versionType=${vt}`, {
          method: 'POST',
          headers: { 'x-api-key': apiKey, 'Content-Type': 'application/octet-stream' },
          body: out
        });
        const text = await r.text();
        return json(res, r.ok ? 200 : r.status, r.ok ? { ok: true, response: text } : { error: `Roblox returned ${r.status}: ${text}` });
      }
    }
    json(res, 404, { error: 'Not found' });
  } catch (e) {
    json(res, 500, { error: e.message });
  }
});
server.listen(PORT, () => console.log('Listening on ' + PORT));
