'use strict';

/**
 * ╔══════════════════════════════════════════════════╗
 * ║   ZEETASI LICENSE SERVER V1.0                    ║
 * ║   Jalankan di VPS: node license-server.js        ║
 * ╚══════════════════════════════════════════════════╝
 *
 * CARA PAKAI:
 *   1. Upload file ini ke VPS
 *   2. Jalankan: node license-server.js
 *   3. Catat TOKEN yang muncul di layar
 *   4. Di bot Telegram, ketik:
 *      /setlicenseserver [IP_VPS] [PORT] [TOKEN]
 *
 * KONFIGURASI (opsional, edit di bawah):
 */

// ─── KONFIGURASI ─────────────────────────────────────
const CONFIG = {
  // Port server (default 3001, bisa diubah)
  PORT: parseInt(process.env.PORT) || 3001,

  // Admin token — PENTING: ganti ini atau biarkan auto-generate
  // Jika diisi di sini, token ini yang dipakai setiap kali server jalan
  // Jika dikosongkan (''), token akan di-generate otomatis tiap restart
  ADMIN_TOKEN: process.env.ADMIN_TOKEN || '',

  // Maks berapa VPS/mesin per satu lisensi key
  MAX_MACHINES_DEFAULT: 1,

  // File database lisensi (otomatis dibuat)
  LICENSE_FILE: require('path').join(__dirname, 'licenses.json'),
};
// ────────────────────────────────────────────────────

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const url    = require('url');

// Generate token otomatis jika tidak diset
const ADMIN_TOKEN = CONFIG.ADMIN_TOKEN || crypto.randomBytes(24).toString('hex');

// ─── DATABASE ────────────────────────────────────────
let db = { licenses: {}, revoked: [], stats: { created: 0, validated: 0, activated: 0 } };

function loadDB() {
  try {
    if (fs.existsSync(CONFIG.LICENSE_FILE)) {
      db = JSON.parse(fs.readFileSync(CONFIG.LICENSE_FILE, 'utf8'));
      if (!db.licenses) db.licenses = {};
      if (!db.revoked)  db.revoked  = [];
      if (!db.stats)    db.stats    = { created: 0, validated: 0, activated: 0 };
    }
  } catch (e) { console.error('[DB] Load error:', e.message); }
}

function saveDB() {
  try { fs.writeFileSync(CONFIG.LICENSE_FILE, JSON.stringify(db, null, 2), 'utf8'); }
  catch (e) { console.error('[DB] Save error:', e.message); }
}
loadDB();

// ─── HELPERS ─────────────────────────────────────────
function genKey(prefix = 'ZTS') {
  const p = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `${prefix}-${p()}-${p()}-${p()}`;
}
function hashMachine(id) {
  return crypto.createHash('sha256').update(String(id)).digest('hex').substring(0, 16);
}
function isExpired(lic) {
  return lic.expiredAt ? new Date(lic.expiredAt) < new Date() : false;
}
function daysLeft(lic) {
  if (!lic.expiredAt) return -1; // lifetime
  return Math.max(0, Math.ceil((new Date(lic.expiredAt) - new Date()) / 86400000));
}
function sendJSON(res, code, data) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 10240) { req.destroy(); reject(new Error('Body too large')); } });
    req.on('end',  () => { try { resolve(body ? JSON.parse(body) : {}); } catch { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}
function isAdmin(req) {
  const t = req.headers['x-admin-token'] || (req.headers['authorization'] || '').replace('Bearer ', '');
  return t === ADMIN_TOKEN;
}
function log(msg) {
  console.log(`[${new Date().toISOString().replace('T', ' ').slice(0, 19)}] ${msg}`);
}

// ─── HTTP SERVER ─────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const p  = url.parse(req.url, true).pathname.replace(/\/$/, '') || '/';
  const m  = req.method.toUpperCase();
  log(`${m} ${p}`);

  // ── GET / ── Status server
  if (m === 'GET' && p === '/') {
    const total  = Object.keys(db.licenses).length;
    const active = Object.values(db.licenses).filter(l => !isExpired(l) && !db.revoked.includes(l.key)).length;
    return sendJSON(res, 200, {
      service: 'Zeetasi License Server V1.0',
      status:  'running',
      time:    new Date().toISOString(),
      stats: { total_licenses: total, active_licenses: active, revoked: db.revoked.length, ...db.stats }
    });
  }

  // ── POST /api/validate ── Validasi lisensi (dari script user)
  if (m === 'POST' && p === '/api/validate') {
    let body; try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { valid: false, message: e.message }); }
    const { key, machine_id } = body;
    if (!key || !machine_id) return sendJSON(res, 400, { valid: false, message: 'key dan machine_id wajib' });

    const lic = db.licenses[key.toUpperCase()];
    if (!lic)                              return sendJSON(res, 404, { valid: false, message: 'Lisensi tidak ditemukan' });
    if (db.revoked.includes(lic.key))      return sendJSON(res, 403, { valid: false, message: 'Lisensi telah dicabut' });
    if (isExpired(lic))                    return sendJSON(res, 403, { valid: false, message: 'Lisensi sudah kadaluarsa' });

    // Cek mesin
    const mHash = hashMachine(machine_id);
    if (!lic.machines) lic.machines = [];
    if (!lic.machines.includes(mHash)) {
      if (lic.machines.length >= (lic.maxMachines || CONFIG.MAX_MACHINES_DEFAULT)) {
        return sendJSON(res, 403, { valid: false, message: `Lisensi sudah dipakai di ${lic.machines.length} mesin. Hubungi admin untuk reset.` });
      }
      lic.machines.push(mHash);
    }

    lic.lastValidated = new Date().toISOString();
    lic.validationCount = (lic.validationCount || 0) + 1;
    db.stats.validated++;
    saveDB();

    return sendJSON(res, 200, {
      valid: true, message: 'Lisensi valid ✅',
      key: lic.key, owner: lic.owner, type: lic.type,
      days_left: daysLeft(lic), expired_at: lic.expiredAt || 'Lifetime', note: lic.note || ''
    });
  }

  // ── POST /api/activate ── Aktivasi pertama kali
  if (m === 'POST' && p === '/api/activate') {
    let body; try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { success: false, message: e.message }); }
    const { key, machine_id, machine_name } = body;
    if (!key || !machine_id) return sendJSON(res, 400, { success: false, message: 'key dan machine_id wajib' });

    const lic = db.licenses[key.toUpperCase()];
    if (!lic)                         return sendJSON(res, 404, { success: false, message: 'Lisensi tidak ditemukan' });
    if (db.revoked.includes(lic.key)) return sendJSON(res, 403, { success: false, message: 'Lisensi dicabut' });
    if (isExpired(lic))               return sendJSON(res, 403, { success: false, message: 'Lisensi kadaluarsa' });

    const mHash = hashMachine(machine_id);
    if (!lic.machines) lic.machines = [];
    if (lic.machines.includes(mHash)) return sendJSON(res, 200, { success: true, message: 'Sudah aktif di mesin ini ✅', already_activated: true, owner: lic.owner, days_left: daysLeft(lic) });
    if (lic.machines.length >= (lic.maxMachines || CONFIG.MAX_MACHINES_DEFAULT)) {
      return sendJSON(res, 403, { success: false, message: `Batas aktivasi (${lic.maxMachines || 1} mesin) tercapai. Hubungi admin.` });
    }

    lic.machines.push(mHash);
    lic.activatedAt = lic.activatedAt || new Date().toISOString();
    if (machine_name) { if (!lic.machineNames) lic.machineNames = []; lic.machineNames.push(String(machine_name).slice(0, 100)); }
    db.stats.activated++;
    saveDB();
    return sendJSON(res, 200, { success: true, message: 'Lisensi berhasil diaktivasi ✅', key: lic.key, owner: lic.owner, days_left: daysLeft(lic), expired_at: lic.expiredAt || 'Lifetime' });
  }

  // ─────────── ADMIN ENDPOINTS ───────────────────────
  if (!isAdmin(req)) {
    // Hanya endpoint publik di atas, sisanya butuh admin token
    if (p.startsWith('/api/admin') || (m === 'POST' && ['/api/admin/create','/api/admin/revoke','/api/admin/restore','/api/admin/delete','/api/admin/reset-machines'].includes(p))) {
      return sendJSON(res, 401, { success: false, message: 'Unauthorized: X-Admin-Token salah atau tidak ada' });
    }
  }

  // ── POST /api/admin/create ── Buat lisensi
  if (m === 'POST' && p === '/api/admin/create') {
    let body; try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { success: false, message: e.message }); }
    const { owner = 'Unknown', type = 'standard', duration = 30, max_machines = 1, note = '', custom_key = null } = body;
    const key = custom_key ? custom_key.toUpperCase() : genKey('ZTS');
    if (db.licenses[key]) return sendJSON(res, 409, { success: false, message: 'Key sudah ada' });

    const expiredAt = duration > 0 ? new Date(Date.now() + duration * 86400000).toISOString() : null;
    db.licenses[key] = { key, owner, type, duration, expiredAt, maxMachines: max_machines, machines: [], machineNames: [], note, createdAt: new Date().toISOString(), activatedAt: null, validationCount: 0 };
    db.stats.created++;
    saveDB();
    log(`[CREATE] Key: ${key} | Owner: ${owner} | Hari: ${duration || 'Lifetime'}`);
    return sendJSON(res, 201, { success: true, message: 'Lisensi dibuat ✅', key, owner, type, expired_at: expiredAt || 'Lifetime', days: duration || 'Lifetime' });
  }

  // ── GET /api/admin/list ── List semua lisensi
  if (m === 'GET' && p === '/api/admin/list') {
    const list = Object.values(db.licenses).map(l => ({ key: l.key, owner: l.owner, type: l.type, expired_at: l.expiredAt || 'Lifetime', days_left: daysLeft(l), is_expired: isExpired(l), is_revoked: db.revoked.includes(l.key), machines: l.machines?.length || 0, max_machines: l.maxMachines || 1, created_at: l.createdAt, activations: l.validationCount || 0, note: l.note || '' }));
    return sendJSON(res, 200, { success: true, total: list.length, licenses: list });
  }

  // ── GET /api/admin/info/:key ── Detail satu lisensi
  const infoM = p.match(/^\/api\/admin\/info\/(.+)$/);
  if (m === 'GET' && infoM) {
    const k = infoM[1].toUpperCase();
    const l = db.licenses[k];
    if (!l) return sendJSON(res, 404, { success: false, message: 'Tidak ditemukan' });
    return sendJSON(res, 200, { success: true, license: { ...l, days_left: daysLeft(l), is_expired: isExpired(l), is_revoked: db.revoked.includes(k) } });
  }

  // ── POST /api/admin/revoke ── Cabut lisensi
  if (m === 'POST' && p === '/api/admin/revoke') {
    let body; try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { success: false, message: e.message }); }
    const key = (body.key || '').toUpperCase();
    if (!db.licenses[key]) return sendJSON(res, 404, { success: false, message: 'Tidak ditemukan' });
    if (!db.revoked.includes(key)) { db.revoked.push(key); saveDB(); }
    log(`[REVOKE] Key: ${key}`);
    return sendJSON(res, 200, { success: true, message: `Lisensi ${key} dicabut` });
  }

  // ── POST /api/admin/restore ── Pulihkan lisensi
  if (m === 'POST' && p === '/api/admin/restore') {
    let body; try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { success: false, message: e.message }); }
    const key = (body.key || '').toUpperCase();
    db.revoked = db.revoked.filter(k => k !== key);
    saveDB();
    log(`[RESTORE] Key: ${key}`);
    return sendJSON(res, 200, { success: true, message: `Lisensi ${key} dipulihkan` });
  }

  // ── POST /api/admin/reset-machines ── Reset mesin
  if (m === 'POST' && p === '/api/admin/reset-machines') {
    let body; try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { success: false, message: e.message }); }
    const key = (body.key || '').toUpperCase();
    if (!db.licenses[key]) return sendJSON(res, 404, { success: false, message: 'Tidak ditemukan' });
    db.licenses[key].machines     = [];
    db.licenses[key].machineNames = [];
    saveDB();
    log(`[RESET-MACHINES] Key: ${key}`);
    return sendJSON(res, 200, { success: true, message: `Mesin ${key} direset` });
  }

  // ── POST /api/admin/delete ── Hapus lisensi
  if (m === 'POST' && p === '/api/admin/delete') {
    let body; try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { success: false, message: e.message }); }
    const key = (body.key || '').toUpperCase();
    if (!db.licenses[key]) return sendJSON(res, 404, { success: false, message: 'Tidak ditemukan' });
    delete db.licenses[key];
    db.revoked = db.revoked.filter(k => k !== key);
    saveDB();
    log(`[DELETE] Key: ${key}`);
    return sendJSON(res, 200, { success: true, message: `Lisensi ${key} dihapus` });
  }

  // ── 404 ──
  return sendJSON(res, 404, { success: false, message: `${m} ${p} tidak ditemukan` });
});

// ─── START ───────────────────────────────────────────
server.listen(CONFIG.PORT, '0.0.0.0', () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║   ZEETASI LICENSE SERVER V1.0 — BERJALAN         ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
  console.log(`  📡 Port           : ${CONFIG.PORT}`);
  console.log(`  📁 Database       : ${CONFIG.LICENSE_FILE}`);
  console.log(`  📋 Total Lisensi  : ${Object.keys(db.licenses).length}`);
  console.log('');
  console.log('  ┌─────────────────────────────────────────────┐');
  console.log('  │  🔑 ADMIN TOKEN (salin untuk bot Telegram)  │');
  console.log(`  │  ${ADMIN_TOKEN.padEnd(45)} │`);
  console.log('  └─────────────────────────────────────────────┘');
  console.log('');
  console.log('  📌 LANGKAH SELANJUTNYA:');
  console.log('  Di bot Telegram, kirim perintah ini ke Owner:');
  console.log('');

  // Coba deteksi IP publik
  require('https').get('https://api.ipify.org', (r) => {
    let ip = '';
    r.on('data', d => { ip += d; });
    r.on('end', () => {
      ip = ip.trim();
      console.log(`  /setlicenseserver ${ip} ${CONFIG.PORT} ${ADMIN_TOKEN}`);
      console.log('');
      console.log(`  Atau jika IP berbeda:`);
      console.log(`  /setlicenseserver [IP_VPS_ANDA] ${CONFIG.PORT} ${ADMIN_TOKEN}`);
      console.log('');
      console.log('  ─────────────────────────────────────────────');
      console.log('  ENDPOINT API:');
      console.log(`  GET  http://0.0.0.0:${CONFIG.PORT}/                     Status`);
      console.log(`  POST http://0.0.0.0:${CONFIG.PORT}/api/validate          Validasi key`);
      console.log(`  POST http://0.0.0.0:${CONFIG.PORT}/api/activate          Aktivasi key`);
      console.log(`  POST http://0.0.0.0:${CONFIG.PORT}/api/admin/create      Buat lisensi`);
      console.log(`  GET  http://0.0.0.0:${CONFIG.PORT}/api/admin/list        Daftar lisensi`);
      console.log(`  POST http://0.0.0.0:${CONFIG.PORT}/api/admin/revoke      Cabut lisensi`);
      console.log(`  POST http://0.0.0.0:${CONFIG.PORT}/api/admin/delete      Hapus lisensi`);
      console.log('');
    });
  }).on('error', () => {
    console.log(`  /setlicenseserver [IP_VPS] ${CONFIG.PORT} ${ADMIN_TOKEN}`);
    console.log('');
  });
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Port ${CONFIG.PORT} sudah digunakan!`);
    console.error(`   Ganti PORT: PORT=3002 node license-server.js`);
  } else {
    console.error('❌ Server error:', err.message);
  }
  process.exit(1);
});

process.on('SIGINT',  () => { saveDB(); console.log('\n✅ Server dihentikan.'); process.exit(0); });
process.on('SIGTERM', () => { saveDB(); console.log('\n✅ Server dihentikan.'); process.exit(0); });
infoM) {
    const k = infoM[1].toUpperCase();
    const l = db.licenses[k];
    if (!l) return sendJSON(res, 404, { success: false, message: 'Tidak ditemukan' });
    return sendJSON(res, 200, { success: true, license: { ...l, days_left: daysLeft(l), is_expired: isExpired(l), is_revoked: db.revoked.includes(k) } });
  }

  // ── POST /api/admin/revoke ── Cabut lisensi
  if (m === 'POST' && p === '/api/admin/revoke') {
    let body; try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { success: false, message: e.message }); }
    const key = (body.key || '').toUpperCase();
    if (!db.licenses[key]) return sendJSON(res, 404, { success: false, message: 'Tidak ditemukan' });
    if (!db.revoked.includes(key)) { db.revoked.push(key); saveDB(); }
    log(`[REVOKE] Key: ${key}`);
    return sendJSON(res, 200, { success: true, message: `Lisensi ${key} dicabut` });
  }

  // ── POST /api/admin/restore ── Pulihkan lisensi
  if (m === 'POST' && p === '/api/admin/restore') {
    let body; try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { success: false, message: e.message }); }
    const key = (body.key || '').toUpperCase();
    db.revoked = db.revoked.filter(k => k !== key);
    saveDB();
    log(`[RESTORE] Key: ${key}`);
    return sendJSON(res, 200, { success: true, message: `Lisensi ${key} dipulihkan` });
  }

  // ── POST /api/admin/reset-machines ── Reset mesin
  if (m === 'POST' && p === '/api/admin/reset-machines') {
    let body; try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { success: false, message: e.message }); }
    const key = (body.key || '').toUpperCase();
    if (!db.licenses[key]) return sendJSON(res, 404, { success: false, message: 'Tidak ditemukan' });
    db.licenses[key].machines     = [];
    db.licenses[key].machineNames = [];
    saveDB();
    log(`[RESET-MACHINES] Key: ${key}`);
    return sendJSON(res, 200, { success: true, message: `Mesin ${key} direset` });
  }

  // ── POST /api/admin/delete ── Hapus lisensi
  if (m === 'POST' && p === '/api/admin/delete') {
    let body; try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { success: false, message: e.message }); }
    const key = (body.key || '').toUpperCase();
    if (!db.licenses[key]) return sendJSON(res, 404, { success: false, message: 'Tidak ditemukan' });
    delete db.licenses[key];
    db.revoked = db.revoked.filter(k => k !== key);
    saveDB();
    log(`[DELETE] Key: ${key}`);
    return sendJSON(res, 200, { success: true, message: `Lisensi ${key} dihapus` });
  }

  // ── 404 ──
  return sendJSON(res, 404, { success: false, message: `${m} ${p} tidak ditemukan` });
});

// ─── START ───────────────────────────────────────────
server.listen(CONFIG.PORT, '0.0.0.0', () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║   ZEETASI LICENSE SERVER V1.0 — BERJALAN         ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
  console.log(`  📡 Port           : ${CONFIG.PORT}`);
  console.log(`  📁 Database       : ${CONFIG.LICENSE_FILE}`);
  console.log(`  📋 Total Lisensi  : ${Object.keys(db.licenses).length}`);
  console.log('');
  console.log('  ┌─────────────────────────────────────────────┐');
  console.log('  │  🔑 ADMIN TOKEN (salin untuk bot Telegram)  │');
  console.log(`  │  ${ADMIN_TOKEN.padEnd(45)} │`);
  console.log('  └─────────────────────────────────────────────┘');
  console.log('');
  console.log('  📌 LANGKAH SELANJUTNYA:');
  console.log('  Di bot Telegram, kirim perintah ini ke Owner:');
  console.log('');

  // Coba deteksi IP publik
  require('https').get('https://api.ipify.org', (r) => {
    let ip = '';
    r.on('data', d => { ip += d; });
    r.on('end', () => {
      ip = ip.trim();
      console.log(`  /setlicenseserver ${ip} ${CONFIG.PORT} ${ADMIN_TOKEN}`);
      console.log('');
      console.log(`  Atau jika IP berbeda:`);
      console.log(`  /setlicenseserver [IP_VPS_ANDA] ${CONFIG.PORT} ${ADMIN_TOKEN}`);
      console.log('');
      console.log('  ─────────────────────────────────────────────');
      console.log('  ENDPOINT API:');
      console.log(`  GET  http://0.0.0.0:${CONFIG.PORT}/                     Status`);
      console.log(`  POST http://0.0.0.0:${CONFIG.PORT}/api/validate          Validasi key`);
      console.log(`  POST http://0.0.0.0:${CONFIG.PORT}/api/activate          Aktivasi key`);
      console.log(`  POST http://0.0.0.0:${CONFIG.PORT}/api/admin/create      Buat lisensi`);
      console.log(`  GET  http://0.0.0.0:${CONFIG.PORT}/api/admin/list        Daftar lisensi`);
      console.log(`  POST http://0.0.0.0:${CONFIG.PORT}/api/admin/revoke      Cabut lisensi`);
      console.log(`  POST http://0.0.0.0:${CONFIG.PORT}/api/admin/delete      Hapus lisensi`);
      console.log('');
    });
  }).on('error', () => {
    console.log(`  /setlicenseserver [IP_VPS] ${CONFIG.PORT} ${ADMIN_TOKEN}`);
    console.log('');
  });
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Port ${CONFIG.PORT} sudah digunakan!`);
    console.error(`   Ganti PORT: PORT=3002 node license-server.js`);
  } else {
    console.error('❌ Server error:', err.message);
  }
  process.exit(1);
});

process.on('SIGINT',  () => { saveDB(); console.log('\n✅ Server dihentikan.'); process.exit(0); });
process.on('SIGTERM', () => { saveDB(); console.log('\n✅ Server dihentikan.'); process.exit(0); });
