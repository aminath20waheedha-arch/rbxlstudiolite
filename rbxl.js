// Minimal reader/editor for Roblox binary place files (.rbxl).
// Only script Source properties are decoded/rewritten; every other chunk is copied byte-for-byte.
const MAGIC = Buffer.from([0x3c,0x72,0x6f,0x62,0x6c,0x6f,0x78,0x21,0x89,0xff,0x0d,0x0a,0x1a,0x0a]); // "<roblox!" + signature
const zlib = require('zlib');
const SCRIPT_CLASSES = new Set(['Script', 'LocalScript', 'ModuleScript']);

function lz4Decompress(src, outLen) {
  const out = Buffer.allocUnsafe(outLen);
  let si = 0, di = 0;
  while (si < src.length) {
    const token = src[si++];
    let lit = token >> 4;
    if (lit === 15) { let b; do { b = src[si++]; lit += b; } while (b === 255); }
    if (!(lit >= 0) || si + lit > src.length || di + lit > outLen) throw new Error('Corrupt or unsupported chunk compression.');
    src.copy(out, di, si, si + lit); si += lit; di += lit;
    if (si >= src.length) break;
    const offset = src[si] | (src[si + 1] << 8); si += 2;
    let ml = token & 15;
    if (ml === 15) { let b; do { b = src[si++]; ml += b; } while (b === 255); }
    ml += 4;
    for (let i = 0; i < ml; i++) { out[di] = out[di - offset]; di++; }
  }
  return out;
}

// Chunks are LZ4-compressed by older Studio versions and ZSTD-compressed by newer ones.
function decompress(src, outLen) {
  if (src.length >= 4 && src.readUInt32LE(0) === 0xfd2fb528) {
    if (typeof zlib.zstdDecompressSync !== 'function') {
      throw new Error('This place uses ZSTD compression, which needs Node 22.15 or newer on the server.');
    }
    return zlib.zstdDecompressSync(src);
  }
  return lz4Decompress(src, outLen);
}

function readRefs(buf, pos, n) {
  const out = new Array(n);
  let acc = 0;
  for (let i = 0; i < n; i++) {
    const v = ((buf[pos + i] << 24) | (buf[pos + n + i] << 16) | (buf[pos + 2 * n + i] << 8) | buf[pos + 3 * n + i]) >>> 0;
    acc += (v >>> 1) ^ -(v & 1);
    out[i] = acc;
  }
  return { values: out, pos: pos + 4 * n };
}

function parse(buf) {
  if (buf.length < 32 || !buf.slice(0, 14).equals(MAGIC)) {
    throw new Error('Not a binary .rbxl file (XML .rbxlx files are not supported).');
  }
  const chunks = [];
  const classes = {};       // classId -> {name, refs[]}
  const names = {};         // ref -> name
  const parents = {};       // ref -> parent ref
  const sourceChunks = [];  // {chunk, classId}
  const classSources = {};  // classId -> array of Buffers
  let pos = 32;
  while (pos + 16 <= buf.length) {
    const name = buf.toString('latin1', pos, pos + 4).replace(/\0/g, '');
    const comp = buf.readUInt32LE(pos + 4);
    const uncomp = buf.readUInt32LE(pos + 8);
    const dataLen = comp === 0 ? uncomp : comp;
    const start = pos, end = pos + 16 + dataLen;
    if (end > buf.length) throw new Error('Corrupt file (chunk overruns file).');
    const chunk = { name, start, end };
    chunks.push(chunk);
    pos = end;
    if (name === 'END') break;
    if (name !== 'INST' && name !== 'PROP' && name !== 'PRNT') continue;
    const raw = buf.slice(start + 16, end);
    const d = comp === 0 ? raw : decompress(raw, uncomp);
    if (name === 'INST') {
      const classId = d.readUInt32LE(0);
      const nl = d.readUInt32LE(4);
      const cname = d.toString('utf8', 8, 8 + nl);
      let p = 8 + nl + 1; // skip service flag
      const count = d.readUInt32LE(p); p += 4;
      classes[classId] = { name: cname, refs: readRefs(d, p, count).values };
    } else if (name === 'PROP') {
      const classId = d.readUInt32LE(0);
      const cls = classes[classId];
      if (!cls) continue;
      const pl = d.readUInt32LE(4);
      const prop = d.toString('utf8', 8, 8 + pl);
      const type = d[8 + pl];
      if (type !== 1) continue;
      const isName = prop === 'Name';
      const isSource = prop === 'Source' && SCRIPT_CLASSES.has(cls.name);
      if (!isName && !isSource) continue;
      let p = 9 + pl;
      const vals = [];
      for (let i = 0; i < cls.refs.length; i++) {
        const l = d.readUInt32LE(p); p += 4;
        vals.push(d.slice(p, p + l)); p += l;
      }
      if (isName) vals.forEach((v, i) => { names[cls.refs[i]] = v.toString('utf8'); });
      else { classSources[classId] = vals; sourceChunks.push({ chunk, classId }); }
    } else if (name === 'PRNT') {
      let p = 1;
      const count = d.readUInt32LE(p); p += 4;
      const kids = readRefs(d, p, count); p = kids.pos;
      const pars = readRefs(d, p, count).values;
      kids.values.forEach((k, i) => { parents[k] = pars[i]; });
    }
  }
  const scripts = [];
  for (const { classId } of sourceChunks) {
    const cls = classes[classId];
    cls.refs.forEach((ref, i) => {
      const parts = [];
      let cur = ref, guard = 0;
      while (cur !== undefined && cur !== -1 && guard++ < 200) {
        parts.unshift(names[cur] ?? '?');
        cur = parents[cur];
      }
      scripts.push({ id: scripts.length, classId, idx: i, className: cls.name, name: names[ref] ?? '?', path: parts.join('/') });
    });
  }
  return { buf, chunks, sourceChunks, classSources, scripts };
}

function getSource(model, id) {
  const s = model.scripts[id];
  return model.classSources[s.classId][s.idx].toString('utf8');
}
function setSource(model, id, text) {
  const s = model.scripts[id];
  model.classSources[s.classId][s.idx] = Buffer.from(text, 'utf8');
  model.dirty = true;
}
function sourceLength(model, id) {
  const s = model.scripts[id];
  return model.classSources[s.classId][s.idx].toString('utf8').length;
}

function build(model) {
  const replace = new Map();
  for (const { chunk, classId } of model.sourceChunks) {
    const orig = model.buf.slice(chunk.start + 16, chunk.end);
    const comp = model.buf.readUInt32LE(chunk.start + 4);
    const uncomp = model.buf.readUInt32LE(chunk.start + 8);
    const d = comp === 0 ? orig : decompress(orig, uncomp);
    const pl = d.readUInt32LE(4);
    const head = d.slice(0, 9 + pl);
    const body = [];
    for (const v of model.classSources[classId]) {
      const l = Buffer.alloc(4); l.writeUInt32LE(v.length);
      body.push(l, v);
    }
    const data = Buffer.concat([head, ...body]);
    const hdr = Buffer.alloc(16);
    hdr.write('PROP', 0, 'latin1');
    hdr.writeUInt32LE(0, 4);              // 0 = stored uncompressed
    hdr.writeUInt32LE(data.length, 8);
    replace.set(chunk, Buffer.concat([hdr, data]));
  }
  const parts = [model.buf.slice(0, 32)];
  for (const c of model.chunks) parts.push(replace.get(c) || model.buf.slice(c.start, c.end));
  return Buffer.concat(parts);
}

module.exports = { parse, getSource, setSource, sourceLength, build, lz4Decompress, decompress };
