const express = require("express");
const crypto = require("crypto");
const { verifyMessage } = require("ethers");
const app = express();

app.use(express.json());

// Stockage en mémoire
const users = {};
const challenges = {};

// 1) Enregistrer un nouveau DID avec ses clés publiques
app.post("/auth/register", (req, res) => {
  const { did, publicKeys, quorum } = req.body;

  if (!did || !publicKeys || !Array.isArray(publicKeys)) {
    return res.status(400).json({ error: "DID et publicKeys requis" });
  }

  if (!quorum || quorum > publicKeys.length) {
    return res.status(400).json({ 
      error: `Quorum doit être entre 1 et ${publicKeys.length}` 
    });
  }

  users[did] = { publicKeys, quorum };
  res.json({ 
    success: true, 
    message: `DID ${did} enregistré avec ${publicKeys.length} clés (quorum: ${quorum})` 
  });
});

// 2) Demander un challenge (début login)
app.get("/auth/challenge/:did", (req, res) => {
  const did = req.params.did;

  if (!users[did]) {
    return res.status(404).json({ error: "DID inconnu" });
  }

  const nonce = crypto.randomUUID();
  challenges[did] = nonce;

  res.json({ did, challenge: nonce });
});

// 3) Vérifier signatures (preuve DID + quorum)
app.post("/auth/verify", (req, res) => {
  const { did, signatures } = req.body;

  const nonce = challenges[did];
  if (!nonce) {
    return res.status(400).json({ error: "Challenge expiré ou inexistant" });
  }

  const user = users[did];
  const required = user.quorum;

  let validCount = 0;
  const validKeys = [];

  for (const proof of signatures) {
    const entry = user.publicKeys.find(k => k.id === proof.keyId);
    if (!entry) continue;

    try {
      const recovered = verifyMessage(nonce, proof.signature);

      if (recovered.toLowerCase() === entry.key.toLowerCase()) {
        validCount++;
        validKeys.push(proof.keyId);
      }
    } catch (e) {
      console.error(`Erreur vérification ${proof.keyId}:`, e.message);
    }
  }

  if (validCount >= required) {
    delete challenges[did];
    return res.json({ 
      authenticated: true, 
      validKeys,
      message: `${validCount}/${required} signatures valides` 
    });
  }

  res.json({ 
    authenticated: false, 
    reason: `Quorum non atteint (${validCount}/${required})` 
  });
});

// 4) Lister les DIDs enregistrés (dev only)
app.get("/auth/users", (req, res) => {
  const userList = Object.entries(users).map(([did, data]) => ({
    did,
    keysCount: data.publicKeys.length,
    quorum: data.quorum
  }));
  res.json(userList);
});

app.listen(3000, () => console.log("🚀 Server running on http://localhost:3000"));