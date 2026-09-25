const express = require('express'), helmet = require('helmet'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const D = require('./db'), { seed } = require('./seed'), { db, TN } = D;
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'); // defina JWT_SECRET para manter sessões após reiniciar
const UP = path.join(__dirname, 'uploads'); fs.mkdirSync(UP, { recursive: true });
if (!db.prepare('SELECT 1 FROM users LIMIT 1').get()) seed();

const app = express();
app.disable('x-powered-by'); app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ['https://fonts.gstatic.com'], scriptSrc: ["'self'", "'unsafe-inline'"], scriptSrcAttr: ["'unsafe-inline'"], imgSrc: ["'self'", 'data:'], upgradeInsecureRequests: null } } }));
app.use(express.json({ limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---- utilidades ----
const PERM = { Administrador: 'vced', Gestor: 'vced', Operador: 'vce', Consulta: 'v' }; // v=ver c=criar e=editar d=excluir
const OSA = ['Em andamento', 'Aguardando peça', 'Aguardando veículo'];
const OSS = ['Aberta', 'Aguardando aprovação', 'Aprovada', ...OSA, 'Concluída', 'Cancelada'];
const today = () => { const d = new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); };
const log = (u, req, txt) => db.prepare('INSERT INTO audit_logs(at,user,ip,txt) VALUES(?,?,?,?)').run(new Date().toISOString(), u ? u.name : '-', req.ip, txt);
const pub = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });
const snap = u => {
  const o = {};
  for (const m in TN) o[m] = m == 'users' && u.role != 'Administrador' ? [] : D.all(m).map(r => { delete r.h; return r; });
  o.audit = u.role == 'Consulta' ? [] : db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200').all().map(a => ({ at: new Date(a.at).toLocaleString('pt-BR'), u: a.user + (a.ip ? ' (' + a.ip + ')' : ''), t: a.txt }));
  return o;
};
const cpfOk = s => { s = s.replace(/\D/g, ''); if (s.length != 11 || /^(\d)\1+$/.test(s)) return 0; for (let t = 9; t < 11; t++) { let x = 0; for (let i = 0; i < t; i++) x += s[i] * (t + 1 - i); if ((x * 10 % 11) % 10 != s[t]) return 0; } return 1; };
const badMail = e => e && !/^\S+@\S+\.\S+$/.test(e) ? 'E-mail inválido.' : '';
const CHK = { // validações do servidor (o front-end não é confiável)
  vehicles: r => /^[A-Z]{3}-?\d[A-Z0-9]\d{2}$/.test(r.plate) ? '' : 'Placa inválida.',
  drivers: r => cpfOk(r.cpf) ? badMail(r.email) : 'CPF inválido.',
  providers: r => [11, 14].includes(r.doc.replace(/\D/g, '').length) ? badMail(r.email) : 'CNPJ/CPF inválido.',
  users: r => /^\S+@\S+\.\S+$/.test(r.email) ? '' : 'E-mail inválido.',
  orders: r => !OSS.includes(r.status) ? 'Status inválido.' : r.start && r.endPrev && r.endPrev < r.start ? 'A previsão de término é anterior ao início.' : r.start && r.endReal && r.endReal < r.start ? 'O término real é anterior ao início.' : r.status == 'Concluída' && (!r.endReal || !r.done || r.kmOs == null) ? 'Para concluir, informe KM, serviços realizados e término real.' : '',
  fuelings: r => r.liters > 0 && r.price > 0 ? '' : 'Litros e valor por litro devem ser positivos.',
};

// integração entre módulos: OS concluída/em andamento e abastecimento atualizam o veículo
function after(m, r) {
  const v = r.vehicle && D.get('vehicles', r.vehicle); if (!v) return;
  const up = o => db.prepare('UPDATE vehicles SET ' + Object.keys(o).map(k => `"${k}"=?`) + ' WHERE id=?').run(...Object.values(o), v.id);
  if (m == 'orders') {
    if (OSA.includes(r.status)) up({ status: 'Em manutenção' });
    if (r.status == 'Concluída') {
      const o = { kmMaint: r.kmOs }; if (r.kmOs > v.km) { o.km = r.kmOs; o.kmDate = today(); } if (v.status == 'Em manutenção') o.status = 'Ativo'; up(o);
      if (r.type == 'Preventiva') db.prepare('UPDATE preventive_maintenance SET lastKm=? WHERE vehicle=?').run(r.kmOs, v.id);
    }
  }
  if (m == 'fuelings' && r.kmF > v.km) up({ km: r.kmF, kmDate: today() });
}

// ---- autenticação ----
const tries = new Map();
app.post('/api/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), k = req.ip + email, t = tries.get(k) || { n: 0, until: 0 };
  if (Date.now() < t.until) return res.status(429).json({ error: `Muitas tentativas. Aguarde ${Math.ceil((t.until - Date.now()) / 1000)} s.` });
  const u = db.prepare('SELECT * FROM users WHERE email=? AND status=?').get(email, 'Ativo');
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.h)) { t.n++; if (t.n >= 5) { t.until = Date.now() + 300000; t.n = 0; } tries.set(k, t); log(null, req, 'falha de login: ' + email.slice(0, 80)); return res.status(401).json({ error: 'E-mail ou senha incorretos.' }); }
  tries.delete(k);
  res.cookie('tk', jwt.sign({ id: u.id }, SECRET, { expiresIn: '8h' }), { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV == 'production', maxAge: 288e5 });
  log(u, req, 'entrou no sistema'); res.json({ user: pub(u), db: snap(u) });
});
app.post('/api/logout', (req, res) => { res.clearCookie('tk'); res.json({ ok: 1 }); });
app.use('/api', (req, res, next) => {
  if (req.method != 'GET' && req.get('X-Requested-With') != 'frotapro') return res.status(403).json({ error: 'Requisição inválida.' }); // defesa CSRF adicional ao SameSite=Strict
  try { const c = (req.headers.cookie || '').match(/(?:^|; )tk=([^;]+)/); const u = D.get('users', jwt.verify(c && c[1], SECRET).id); if (!u || u.status != 'Ativo') throw 0; req.u = u; next(); }
  catch (e) { res.status(401).json({ error: 'Sessão expirada. Entre novamente.' }); }
});
app.get('/api/me', (req, res) => res.json({ user: pub(req.u), db: snap(req.u) }));
app.post('/api/reset', (req, res) => { if (req.u.role != 'Administrador') return res.status(403).json({ error: 'Sem permissão.' }); seed(); const u = D.get('users', 1); res.cookie('tk', jwt.sign({ id: 1 }, SECRET, { expiresIn: '8h' }), { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV == 'production' }); log(u, req, 'restaurou os dados de demonstração'); res.json({ user: pub(u), db: snap(u) }); });

// ---- anexos (PDF/JPG/PNG, até 5 MB, validação por assinatura do arquivo) ----
const MAGIC = { 'application/pdf': b => b.subarray(0, 4).toString() == '%PDF', 'image/png': b => b.subarray(1, 4).toString() == 'PNG', 'image/jpeg': b => b[0] == 0xff && b[1] == 0xd8 };
const EXT = { 'application/pdf': '.pdf', 'image/png': '.png', 'image/jpeg': '.jpg' };
app.post('/api/attachments/:m/:id', express.raw({ type: Object.keys(MAGIC), limit: '5mb' }), (req, res) => {
  const { m, id } = req.params, ct = (req.get('content-type') || '').split(';')[0];
  if (!TN[m] || !PERM[req.u.role].includes('e') || !D.get(m, +id)) return res.status(403).json({ error: 'Sem permissão ou registro inexistente.' });
  if (!Buffer.isBuffer(req.body) || !req.body.length || !MAGIC[ct] || !MAGIC[ct](req.body)) return res.status(400).json({ error: 'Envie um PDF, JPG ou PNG válido (até 5 MB).' });
  const file = crypto.randomUUID() + EXT[ct]; fs.writeFileSync(path.join(UP, file), req.body);
  let name = 'arquivo' + EXT[ct]; try { name = path.basename(decodeURIComponent(req.get('x-filename') || name)).slice(0, 80); } catch (e) {}
  db.prepare('INSERT INTO attachments(ref_table,ref_id,name,mime,size,file,created_at) VALUES(?,?,?,?,?,?,?)').run(m, +id, name, ct, req.body.length, file, new Date().toISOString());
  log(req.u, req, `anexou "${name}" em ${m} #${id}`); res.json({ ok: 1 });
});
app.get('/api/attachments/:m/:id', (req, res) => res.json(db.prepare('SELECT id,name,mime,size,created_at FROM attachments WHERE ref_table=? AND ref_id=?').all(req.params.m, +req.params.id).map(a => ({ ...a }))));
app.get('/api/files/:id', (req, res) => { const a = db.prepare('SELECT * FROM attachments WHERE id=?').get(+req.params.id); if (!a) return res.sendStatus(404); res.set({ 'Content-Type': a.mime, 'X-Content-Type-Options': 'nosniff', 'Content-Disposition': "inline; filename*=UTF-8''" + encodeURIComponent(a.name) }); res.sendFile(path.join(UP, a.file)); });

// ---- CRUD genérico com permissões, validação, auditoria ----
function write(req, res) {
  const m = req.params.m, id = +req.params.id || 0, u = req.u, bad = (s, e) => res.status(s).json({ error: e });
  if (!TN[m]) return bad(404, 'Módulo inexistente.');
  if (!PERM[u.role].includes(id ? 'e' : 'c') || (m == 'users' && u.role != 'Administrador')) return bad(403, 'Sem permissão para esta operação.');
  const old = id ? D.get(m, id) : null; if (id && !old) return bad(404, 'Registro não encontrado.');
  const r = D.clean(m, req.body);
  if (m == 'vehicles') r.plate = r.plate.toUpperCase(); if (m == 'users') r.email = r.email.toLowerCase();
  if (m == 'orders') r.total = (r.labor || 0) + (r.partsV || 0) + (r.other || 0) - (r.disc || 0);
  if (m == 'fuelings') r.total = +((r.liters || 0) * (r.price || 0)).toFixed(2);
  const miss = D.COLS[m].find(c => c.rq && c.n != 'h' && (r[c.n] === null || r[c.n] === '')); if (miss) return bad(400, `Preencha o campo obrigatório: ${miss.n}.`);
  const er = CHK[m] && CHK[m](r); if (er) return bad(400, er);
  if (m == 'users') { const pw = String(req.body.pw || ''); if (pw) { if (pw.length < 6) return bad(400, 'A senha deve ter ao menos 6 caracteres.'); r.h = bcrypt.hashSync(pw, 10); } else if (old) r.h = old.h; else return bad(400, 'Informe uma senha.'); if (old && old.id == u.id && r.status != 'Ativo') return bad(400, 'Você não pode inativar a si mesmo.'); }
  let nid = id;
  try { db.exec('BEGIN'); if (old) D.upd(m, id, r); else nid = D.ins(m, r); after(m, r); db.exec('COMMIT'); }
  catch (e) { try { db.exec('ROLLBACK'); } catch (x) {} return bad(400, /UNIQUE/.test(e.message) ? 'Registro duplicado: placa, prefixo, CPF, CNPJ, e-mail ou código já cadastrado.' : /FOREIGN/.test(e.message) ? 'Referência inválida (veículo, condutor ou prestador inexistente).' : (console.error(e), 'Não foi possível salvar.')); }
  const diff = old ? Object.keys(r).filter(k => k != 'h' && String(old[k] ?? '') != String(r[k] ?? '')).map(k => `${k}: ${old[k] ?? '—'} → ${r[k] ?? '—'}`).join('; ') : '';
  log(u, req, old ? `alterou ${m} #${id}${diff ? ' (' + diff + ')' : ''}` : `criou ${m} #${nid}`);
  res.json({ db: snap(u) });
}
app.post('/api/:m', write); app.put('/api/:m/:id', write);
app.delete('/api/:m/:id', (req, res) => {
  const { m } = req.params, id = +req.params.id, u = req.u;
  if (!TN[m]) return res.status(404).json({ error: 'Módulo inexistente.' });
  if (!PERM[u.role].includes('d') || (m == 'users' && (u.role != 'Administrador' || id == u.id))) return res.status(403).json({ error: 'Sem permissão para excluir.' });
  try { db.prepare(`DELETE FROM ${TN[m]} WHERE id=?`).run(id); }
  catch (e) { return res.status(400).json({ error: /FOREIGN/.test(e.message) ? 'Este registro possui histórico vinculado. Prefira inativar (editar o status).' : 'Não foi possível excluir.' }); }
  db.prepare('DELETE FROM attachments WHERE ref_table=? AND ref_id=?').run(m, id);
  log(u, req, `excluiu ${m} #${id}`); res.json({ db: snap(u) });
});
app.use((err, req, res, next) => res.status(err.status || 500).json({ error: err.type == 'entity.too.large' ? 'Arquivo maior que 5 MB.' : 'Erro inesperado.' }));
app.listen(process.env.PORT || 3000, () => console.log('FrotaPro em http://localhost:' + (process.env.PORT || 3000)));
