// Benchmark corpus: Express cases. `VULN:<type>` marks a flaw expected on that line; findings
// elsewhere are false positives.
const express = require('express');
const db = require('./db');
const app = express();

// ---------------------------------------------------------------- vulnerable

app.get('/v/search', (req, res) => {
  db.query(`SELECT * FROM products WHERE name = '${req.query.q}'`); // VULN:sql_injection
  res.send('ok');
});

app.get('/v/go', (req, res) => {
  res.redirect(req.query.next); // VULN:open_redirect
});

app.post('/v/admin/reset', (req, res) => { // VULN:missing_function_level_authorization
  res.send('reset');
});

// ---------------------------------------------------------------- safe

app.get('/s/search', (req, res) => {
  db.query('SELECT * FROM products WHERE name = ?', [req.query.q]);
  res.send('ok');
});

app.get('/s/home', (req, res) => {
  res.redirect('/home');
});

app.post('/s/admin/reset', requireAdmin, (req, res) => {
  res.send('reset');
});

app.get('/s/health', (req, res) => {
  res.send('ok');
});
