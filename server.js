require('dotenv').config();
const express = require('express');
const path = require('path');
const { CustomerVerifyService } = require('./customer-verify');

const app = express();
const PORT = process.env.PORT || 3457;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Customer Verification Service ───────────────────────────────────
const customerVerify = new CustomerVerifyService();

// Run full verification pipeline on a customer email
app.post('/api/verify-customer', async (req, res) => {
  try {
    const { email, phone, companyName } = req.body || {};
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email address required' });
    }
    const result = await customerVerify.verify(email, { phone, companyName });
    res.json(result);
  } catch (error) {
    console.error('[CustomerVerify] Error:', error);
    res.status(500).json({ error: 'Verification failed: ' + error.message });
  }
});

// Get all past verification results
app.get('/api/verify-customer/results', (req, res) => {
  res.json(customerVerify.getResults());
});

// Get a specific verification by email
app.get('/api/verify-customer/:email', (req, res) => {
  const result = customerVerify.getResult(req.params.email);
  result ? res.json(result) : res.status(404).json({ error: 'No verification found for this email' });
});

// Delete a verification result
app.delete('/api/verify-customer/:email', (req, res) => {
  const deleted = customerVerify.deleteResult(req.params.email);
  deleted ? res.json({ success: true }) : res.status(404).json({ error: 'Not found' });
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  🛡️  Fello Customer Verify`);
  console.log(`  ─────────────────────────────────`);
  console.log(`  Running at http://localhost:${PORT}`);
  console.log(`  Press Ctrl+C to stop\n`);
});
