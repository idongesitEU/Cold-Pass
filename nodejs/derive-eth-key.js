import { HDNodeWallet, pbkdf2, toUtf8Bytes } from "ethers";

/**
 * Derive the nth Ethereum private key (exactly matches IanColeman)
 * and correctly uses the BIP39 passphrase.
 */
export async function deriveEthPrivateKey(mnemonic, passphrase = "", n = 0) {
  if (!Number.isInteger(n) || n < 0) throw new Error("n must be >= 0");

  // Normalize and validate the mnemonic
  const words = mnemonic.trim().split(/\s+/);
  if (words.length < 12) throw new Error("Invalid mnemonic");

  // --- BIP-39 seed derivation with passphrase ---
  // Salt = "mnemonic" + passphrase
  const salt = "mnemonic" + passphrase;
  const mnemonicBuffer = toUtf8Bytes(mnemonic.normalize("NFKD"));
  const saltBuffer = toUtf8Bytes(salt.normalize("NFKD"));

  // Derive seed = PBKDF2(mnemonic, "mnemonic"+passphrase, 2048, 64, HMAC-SHA512)
  const seed = await pbkdf2(
    mnemonicBuffer,
    saltBuffer,
    2048,
    64,
    "sha512"
  );

  // Create root node from the computed seed
  const master = HDNodeWallet.fromSeed(seed);

  // Full Ethereum derivation path (absolute)
  const path = `m/44'/60'/0'/0/${n}`;

  // Derive the child node
  const child = master.derivePath(path);

  return child.privateKey;
}
