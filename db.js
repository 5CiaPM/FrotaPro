// Banco relacional (SQLite embutido do Node ≥ 22.5) com integridade referencial.
// O esquema é declarado em DSL compacta: nome:tipo[!obrigatório][u=único]; tipos t=texto, n=número, r.tabela=chave estrangeira.
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(process.env.DB_FILE || 'frota.db');
db.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL');

// módulo da API -> tabela
const TN = { users: 'users', vehicles: 'vehicles', drivers: 'drivers', orders: 'service_orders', providers: 'service_providers', fuelings: 'fuelings', tires: 'tires', prev: 'preventive_maintenance', docs: 'documents', fines: 'fines', insurance: 'insurance' };
const DEF = {
  users: 'name:t! email:t!u role:t! status:t! h:t',
  vehicles: 'plate:t!u prefix:t!u brand:t! model:t! year:n fuel:t km:n! kmDate:t kmMaint:n status:t! licDue:t owner:t obs:t',
  drivers: 'name:t! cpf:t!u phone:t email:t cnh:t! cnhCat:t cnhDue:t! status:t! vehicle:r.vehicles obs:t',
  providers: 'type:t! name:t! doc:t!u phone:t email:t city:t services:t status:t! obs:t',
  orders: 'vehicle:r.vehicles! provider:r.providers! type:t! prio:t status:t! opened:t start:t endPrev:t endReal:t kmOs:n req:t service:t! diag:t done:t est:n labor:n partsV:n other:n disc:n total:n pay:t',
  fuelings: 'date:t! vehicle:r.vehicles! driver:r.drivers provider:r.providers! fuel:t liters:n! price:n! total:n kmF:n! note:t pay:t',
  tires: 'code:t!u brand:t model:t size:t dot:t value:n vehicle:r.vehicles pos:t km:n status:t!',
  prev: 'vehicle:r.vehicles! item:t! every:n! lastKm:n!',
  docs: 'doc:t! vehicle:r.vehicles! number:t issue:t due:t! obs:t',
  fines: 'vehicle:r.vehicles! driver:r.drivers date:t! place:t orgao:t auto:t desc:t! value:n! due:t points:n status:t!',
  insurance: 'vehicle:r.vehicles! insurer:t! policy:t! start:t due:t! value:n coverage:t deduct:n',
};
const COLS = {};
for (const m in DEF) COLS[m] = DEF[m].split(' ').map(s => { const [, n, t, rq, u] = s.match(/^(\w+):(t|n|r\.\w+)(!?)(u?)$/); return { n, t: t[0], ref: t[0] == 'r' ? t.slice(2) : null, rq: !!rq, u: !!u }; });

for (const m in DEF) db.exec(`CREATE TABLE IF NOT EXISTS ${TN[m]}(id INTEGER PRIMARY KEY AUTOINCREMENT,${COLS[m].map(c => `"${c.n}" ${c.t == 'n' ? 'REAL' : c.t == 'r' ? 'INTEGER' : 'TEXT'}${c.rq ? ' NOT NULL' : ''}${c.u ? ' UNIQUE' : ''}`).join(',')}${COLS[m].filter(c => c.ref).map(c => `,FOREIGN KEY("${c.n}") REFERENCES ${TN[c.ref]}(id)`).join('')})`);
db.exec(`CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,user TEXT,ip TEXT,txt TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attachments(id INTEGER PRIMARY KEY AUTOINCREMENT,ref_table TEXT NOT NULL,ref_id INTEGER NOT NULL,name TEXT,mime TEXT,size INTEGER,file TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_att ON attachments(ref_table,ref_id);
CREATE INDEX IF NOT EXISTS ix_fuel_v ON fuelings(vehicle);CREATE INDEX IF NOT EXISTS ix_os_v ON service_orders(vehicle);`);

const all = m => db.prepare(`SELECT * FROM ${TN[m]} ORDER BY id`).all().map(r => ({ ...r }));
const get = (m, id) => { const r = db.prepare(`SELECT * FROM ${TN[m]} WHERE id=?`).get(id); return r && { ...r }; };
const q = m => COLS[m].map(x => `"${x.n}"`);
const ins = (m, r) => Number(db.prepare(`INSERT INTO ${TN[m]}(${q(m)}) VALUES(${COLS[m].map(() => '?')})`).run(...COLS[m].map(x => r[x.n] ?? null)).lastInsertRowid);
const upd = (m, id, r) => db.prepare(`UPDATE ${TN[m]} SET ${q(m).map(c => c + '=?')} WHERE id=?`).run(...COLS[m].map(x => r[x.n] ?? null), id);
// só aceita colunas conhecidas e converte tipos
const clean = (m, b = {}) => Object.fromEntries(COLS[m].map(c => {
  let v = b[c.n];
  if (c.t == 'n' || c.t == 'r') { v = v === '' || v == null ? null : Number(v); if (Number.isNaN(v)) v = null; } else v = String(v ?? '').trim().slice(0, 500);
  return [c.n, v];
}));
module.exports = { db, TN, COLS, all, get, ins, upd, clean };
