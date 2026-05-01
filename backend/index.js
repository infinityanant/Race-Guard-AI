const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Simulated wallet DB (in-memory)
const wallets = {};

// Track active in-flight requests per user for better concurrency detection
const activeRequests = {};

// Initialize a user wallet
app.post('/api/init', (req, res) => {
  const { userId, balance } = req.body;
  const startBalance = typeof balance === 'number' ? balance : 100;
  wallets[userId] = { balance: startBalance, couponUsed: false, initialBalance: startBalance };
  res.json({ message: 'Wallet initialized', balance: startBalance });
});

// Reset wallet — restores balance and couponUsed for demo purposes
app.post('/api/reset', (req, res) => {
  const { userId } = req.body;
  const wallet = wallets[userId];
  if (!wallet) return res.status(404).json({ error: 'User not found' });
  wallet.balance = wallet.initialBalance;
  wallet.couponUsed = false;
  res.json({ message: 'Wallet reset', balance: wallet.balance, couponUsed: false });
});

// Race condition endpoint — intentionally vulnerable for demo
app.post('/api/redeem', async (req, res) => {
  const { userId } = req.body;
  const wallet = wallets[userId];
  if (!wallet) return res.status(404).json({ error: 'User not found' });
  if (wallet.couponUsed) return res.status(400).json({ error: 'Coupon already used' });

  activeRequests[userId] = (activeRequests[userId] || 0) + 1;
  const concurrentSnapshot = activeRequests[userId];

  await new Promise(r => setTimeout(r, 50));

  activeRequests[userId] = Math.max(0, (activeRequests[userId] || 0) - 1);

  wallet.couponUsed = true;
  wallet.balance += 50;

  logRequest(userId, '/api/redeem', concurrentSnapshot).catch(() => {});

  res.json({ message: 'Coupon redeemed!', newBalance: wallet.balance });
});

// Normal transfer — safe, legitimate human transaction (no race condition)
app.post('/api/transfer', async (req, res) => {
  const { userId, amount } = req.body;
  const wallet = wallets[userId];
  if (!wallet) return res.status(404).json({ error: 'User not found' });

  const transferAmount = typeof amount === 'number' ? amount : 10;
  if (wallet.balance < transferAmount) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }

  const aiDecision = await logRequest(userId, '/api/transfer', 1);
  if (aiDecision && aiDecision.decision === 'block') {
    return res.status(403).json({
      error: 'Transaction blocked by AI',
      riskScore: aiDecision.riskScore,
    });
  }

  wallet.balance -= transferAmount;
  res.json({ message: `Transferred $${transferAmount}`, newBalance: wallet.balance });
});

// Server-side attack simulation
app.post('/api/simulate-attack', async (req, res) => {
  try {
    const { userId, count } = req.body;
    const numRequests = Math.min(count || 10, 50);
    const wallet = wallets[userId];
    if (!wallet) return res.status(404).json({ error: 'User not found' });

    console.log(`[ATTACK] Simulating ${numRequests} concurrent redeem requests for ${userId}`);

    const couponWasUsed = wallet.couponUsed;

    const results = await Promise.all(
      Array.from({ length: numRequests }, async (_, i) => {
        try {
          if (couponWasUsed) {
            return { index: i, status: 'rejected', reason: 'Coupon already used' };
          }
          activeRequests[userId] = (activeRequests[userId] || 0) + 1;
          const concurrentSnapshot = activeRequests[userId];
          await new Promise(r => setTimeout(r, 50));
          activeRequests[userId] = Math.max(0, (activeRequests[userId] || 0) - 1);
          const aiDecision = await logRequest(userId, '/api/redeem', concurrentSnapshot);
          if (!aiDecision) {
            return { index: i, status: 'blocked', decision: 'block', riskScore: 100, reason: 'AI service unreachable' };
          }
          if (aiDecision.decision === 'block' || aiDecision.decision === 'flag') {
            return { index: i, status: 'blocked', decision: aiDecision.decision, riskScore: aiDecision.riskScore };
          }
          wallet.couponUsed = true;
          wallet.balance += 50;
          return { index: i, status: 'success', newBalance: wallet.balance };
        } catch (err) {
          return { index: i, status: 'error', reason: err.message };
        }
      })
    );

    const succeeded = results.filter(r => r.status === 'success');
    const blocked = results.filter(r => r.status === 'blocked');
    const rejected = results.filter(r => r.status === 'rejected');
    const errors = results.filter(r => r.status === 'error');

    res.json({
      totalRequests: numRequests,
      succeeded: succeeded.length,
      blocked: blocked.length,
      rejected: rejected.length,
      errors: errors.length,
      finalBalance: wallet.balance,
      results,
    });
  } catch (err) {
    res.status(500).json({ error: 'Attack simulation failed: ' + err.message });
  }
});

// Get wallet balance
app.get('/api/wallet/:userId', (req, res) => {
  const wallet = wallets[req.params.userId];
  res.json(wallet || { error: 'Not found' });
});

// ---- Request Logger ----
const requestLog = [];

async function logRequest(userId, endpoint, concurrentOverride) {
  const now = Date.now();
  const recentRequests = requestLog.filter(
    r => r.userId === userId && now - r.timestamp < 2000
  );
  const concurrentCount = concurrentOverride ?? recentRequests.length;
  const entry = {
    id: uuidv4(),
    userId,
    endpoint,
    timestamp: now,
    concurrentCount,
    timeSinceLastRequest: recentRequests.length > 0
      ? now - recentRequests[recentRequests.length - 1].timestamp
      : 9999,
  };
  requestLog.push(entry);
  try {
    const aiRes = await fetch('http://localhost:5001/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry),
    });
    const decision = await aiRes.json();
    entry.decision = decision;
    return decision;
  } catch (e) {
    console.error('[AI] Service unreachable:', e.message);
    return null;
  }
}

// Full app reset
app.post('/api/full-reset', (req, res) => {
  for (const key of Object.keys(wallets)) delete wallets[key];
  for (const key of Object.keys(activeRequests)) delete activeRequests[key];
  requestLog.length = 0;
  res.json({ message: 'Full reset complete', walletsCleared: true, logsCleared: true });
});

// Expose logs to frontend dashboard
app.get('/api/logs', (req, res) => {
  res.json(requestLog.slice(-100));
});

// ──────────────────────────────────────────────
// NEW: /api/audit — SSE proxy to AI service
// ──────────────────────────────────────────────
app.post('/api/audit', async (req, res) => {
  const { code, language } = req.body;

  if (!code || !code.trim()) {
    return res.status(400).json({ error: 'No code provided' });
  }

  // Set SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  try {
    // Forward to AI service
    const aiRes = await fetch('http://localhost:5001/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, language }),
    });

    if (!aiRes.ok) {
      const errText = await aiRes.text();
      res.write(`data: ${JSON.stringify({ step: 0, status: 'error', label: 'Audit failed', error: errText })}\n\n`);
      res.end();
      return;
    }

    // Pipe the SSE stream from AI service to frontend
    const reader = aiRes.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value, { stream: true });
      res.write(chunk);
    }
  } catch (err) {
    console.error('[AUDIT] Proxy error:', err.message);
    res.write(`data: ${JSON.stringify({ step: 0, status: 'error', label: 'Service error', error: err.message })}\n\n`);
  }

  res.end();
});

app.listen(4000, () => console.log('Backend running on :4000'));
