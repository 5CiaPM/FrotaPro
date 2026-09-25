# FrotaPro – Gestão de Frota

Back-end Node.js (Express) + banco relacional SQLite com chaves estrangeiras + front-end responsivo em `public/index.html`.

## Como rodar
```
npm install
npm start          # http://localhost:3000
```
Requer Node 22.5 ou superior. No 1º início o banco `frota.db` é criado com dados de demonstração.
Variáveis: `PORT`, `JWT_SECRET` (obrigatória em produção), `DB_FILE`, `NODE_ENV=production` (cookie Secure; use HTTPS).

## Logins de demonstração
admin@frota.com / admin123 · gestor@frota.com / gestor123 · operador@frota.com / operador123 · consulta@frota.com / consulta123
**Troque essas senhas (ou apague os usuários demo) antes de usar de verdade.**

## Estrutura
- `db.js` – esquema (tabelas: users, vehicles, drivers, service_orders, service_providers, fuelings, tires, preventive_maintenance, documents, fines, insurance, audit_logs, attachments), FKs e helpers
- `seed.js` – dados fictícios (também em Configurações → Restaurar demonstração)
- `server.js` – autenticação, permissões, CRUD, validações, regras de negócio, auditoria, anexos
- `public/index.html` – interface

## API (JSON, cookie de sessão HttpOnly; requisições de escrita exigem o cabeçalho `X-Requested-With: frotapro`)
`POST /api/login` · `POST /api/logout` · `GET /api/me` · `POST /api/:modulo` · `PUT /api/:modulo/:id` · `DELETE /api/:modulo/:id` · `GET|POST /api/attachments/:modulo/:id` · `GET /api/files/:id` · `POST /api/reset` (admin)
Módulos: vehicles, drivers, orders, providers, fuelings, tires, prev, docs, fines, insurance, users.

## Segurança implementada
bcrypt · JWT em cookie HttpOnly/SameSite=Strict · bloqueio após 5 tentativas (5 min) · permissões por perfil no servidor · consultas SQL parametrizadas · escape de HTML no front-end + CSP (helmet) · upload validado por tipo, assinatura e limite de 5 MB · auditoria com usuário, IP e valores antes → depois.
