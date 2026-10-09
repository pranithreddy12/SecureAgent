// VULNERABLE SHOP (Node) -- A DELIBERATELY INSECURE DEMO. NOT REAL. DO NOT DEPLOY.
// Flaws are intentional so SecureAgent's `demo` command has JavaScript to analyse.
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query(`SELECT * FROM users WHERE id = ${id}`);   // SQL injection (template literal)
  res.send('ok');
});

app.get('/go', (req, res) => {
  res.redirect(req.query.next);                       // open redirect
});

app.post('/admin/reset', resetHandler);               // no authentication middleware

app.get('/account', requireAuth, accountHandler);     // protected: correctly not reported

app.listen(3000);
