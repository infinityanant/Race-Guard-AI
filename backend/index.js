const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: '2mb' }));

// 🔥 AI SERVICE URL (FIXED)
const AI_URL = "https://raceguard-ai.onrender.com";

// Simulated wallet DB (in-memory)
const wallets = {};
const activeRequests = {};
const requestLog = [];

// ──────────────────────────────────────────────
// INIT WALLET
// ──────────────────────────────────────────────
app.post('/api/init', (req, res) => {
  const { userId, balance } = req.body;
  const startBalance = typeof balance === 'number' ? balance : 100;

  wallets[userId] = {
    balance: startBalance,
    couponUsed: false,
    initialBalance: startBalance
  };

  res.json({ message: 'Wallet initialized', balance: startBalance });
});

// ──────────────────────────────────────────────
// RESET WALLET
// ──────────────────────────────────────────────
app.post('/api/reset', (req, res) => {
  const { userId } = req.body;
  const wallet = wallets[userId];

  if (!wallet) return res.status(404).json({ error: 'User not found' });

  wallet.balance = wallet.initialBalance;
  wallet.couponUsed = false;

  res.json({
    message: 'Wallet reset',
    balance: wallet.balance,
    couponUsed: false
  });
});

// ──────────────────────────────────────────────
// VULNERABLE ENDPOINT
// ──────────────────────────────────────────────
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

  logRequest(userId, '/api/redeem', concurrentSnapshot).catch(() => { });

  res.json({ message: 'Coupon redeemed!', newBalance: wallet.balance });
});

// ──────────────────────────────────────────────
// SAFE TRANSFER
// ──────────────────────────────────────────────
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
      riskScore: aiDecision.riskScore
    });
  }

  wallet.balance -= transferAmount;

  res.json({
    message: `Transferred $${transferAmount}`,
    newBalance: wallet.balance
  });
});

// ──────────────────────────────────────────────
// ATTACK SIMULATION
// ──────────────────────────────────────────────
app.post('/api/simulate-attack', async (req, res) => {
  try {
    const { userId, count } = req.body;
    const numRequests = Math.min(count || 10, 50);

    const wallet = wallets[userId];
    if (!wallet) return res.status(404).json({ error: 'User not found' });

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
            return { index: i, status: 'blocked', reason: 'AI unreachable' };
          }

          if (aiDecision.decision !== 'allow') {
            return {
              index: i,
              status: 'blocked',
              decision: aiDecision.decision,
              riskScore: aiDecision.riskScore
            };
          }

          wallet.couponUsed = true;
          wallet.balance += 50;

          return { index: i, status: 'success', newBalance: wallet.balance };

        } catch (err) {
          return { index: i, status: 'error', reason: err.message };
        }
      })
    );

    res.json({
      totalRequests: numRequests,
      succeeded: results.filter(r => r.status === 'success').length,
      blocked: results.filter(r => r.status === 'blocked').length,
      finalBalance: wallet.balance,
      results
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────
// LOG REQUEST + AI CALL
// ──────────────────────────────────────────────
async function logRequest(userId, endpoint, concurrentOverride) {
  const now = Date.now();

  const recentRequests = requestLog.filter(
    r => r.userId === userId && now - r.timestamp < 2000
  );

  const entry = {
    id: uuidv4(),
    userId,
    endpoint,
    timestamp: now,
    concurrentCount: concurrentOverride ?? recentRequests.length,
    timeSinceLastRequest:
      recentRequests.length > 0
        ? now - recentRequests[recentRequests.length - 1].timestamp
        : 9999
  };

  requestLog.push(entry);

  try {
    const aiRes = await fetch(`${AI_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry)
    });

    const decision = await aiRes.json();
    return decision;

  } catch (e) {
    console.error('[AI ERROR]', e.message);
    return null;
  }
}

// ──────────────────────────────────────────────
// SSE AUDIT PROXY
// ──────────────────────────────────────────────
app.post('/api/audit', async (req, res) => {
  const { code, language } = req.body;

  if (!code || !code.trim()) {
    return res.status(400).json({ error: 'No code provided' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  try {
    const aiRes = await fetch(`${AI_URL}/audit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, language })
    });

    const reader = aiRes.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(decoder.decode(value));
    }

  } catch (err) {
    res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
  }

  res.end();
});

// ──────────────────────────────────────────────
// SERVER START
// ──────────────────────────────────────────────
const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log("🚀 Backend running on port", PORT);
});