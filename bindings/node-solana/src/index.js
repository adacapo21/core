const { exportWallet } = require("@open-wallet-standard/core");

function owsToSolanaKeypair(walletNameOrId, options = {}) {
  const { Keypair } = require("@solana/web3.js");
  const exported = exportWallet(walletNameOrId, options.passphrase, options.vaultPath);
  let privateKeyBytes;
  try {
    const keys = JSON.parse(exported);
    const hex = keys.ed25519 ?? "";
    const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
    privateKeyBytes = Uint8Array.from(clean.match(/.{2}/g).map((b) => parseInt(b, 16)));
  } catch {
    throw new Error("Mnemonic wallets: use @open-wallet-standard/core signMessage/signTransaction directly, or import with a private key for Keypair access.");
  }
  if (privateKeyBytes.length === 32) {
    const { ed25519 } = require("@noble/curves/ed25519");
    const publicKey = ed25519.getPublicKey(privateKeyBytes);
    const fullKey = new Uint8Array(64);
    fullKey.set(privateKeyBytes, 0);
    fullKey.set(publicKey, 32);
    return Keypair.fromSecretKey(fullKey);
  }
  if (privateKeyBytes.length === 64) return Keypair.fromSecretKey(privateKeyBytes);
  throw new Error(`Unexpected key length: ${privateKeyBytes.length} bytes`);
}

module.exports = { owsToSolanaKeypair };
