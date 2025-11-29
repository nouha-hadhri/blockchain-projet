const { Wallet } = require("ethers");
const fs = require("fs");
const path = require("path");

const challenge = process.argv[2];

if (!challenge) {
  console.log("Usage: node sign.js <challenge>");
  process.exit();
}

const keysFile = path.join(__dirname, ".keys.json");

let keys;

// Si les clés existent déjà, les charger
if (fs.existsSync(keysFile)) {
  console.log("📂 Chargement des clés existantes...\n");
  const savedKeys = JSON.parse(fs.readFileSync(keysFile, "utf8"));
  keys = savedKeys.map(k => new Wallet(k.privateKey));
} else {
  console.log("🔑 Génération de nouvelles clés...\n");
  keys = [
    Wallet.createRandom(),
    Wallet.createRandom(),
    Wallet.createRandom()
  ];
  
  // Sauvegarder les clés
  const keysToSave = keys.map((w, i) => ({
    id: `key${i + 1}`,
    address: w.address,
    privateKey: w.privateKey
  }));
  
  fs.writeFileSync(keysFile, JSON.stringify(keysToSave, null, 2));
  console.log("💾 Clés sauvegardées dans .keys.json\n");
}

console.log("=== Public Keys (à copier dans le serveur) ===");
keys.forEach((w, i) => {
  console.log(`key${i + 1}: ${w.address}`);
});

console.log("\n=== Signatures (payload pour /auth/verify) ===");
const signatures = keys.map((w, i) => ({
  keyId: `key${i + 1}`,
  signature: w.signMessageSync(challenge)
}));

console.log(JSON.stringify(signatures, null, 2));