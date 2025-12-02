// scripts/mitm-demo.ts
//
// MITM demo for your report & video.
// Run with:  npx ts-node scripts/mitm-demo.ts
//
// Requires: Node 18+ (for global crypto.webcrypto)

import { webcrypto } from "crypto";
const subtle = webcrypto.subtle;

// -----------------------------
// Helpers
// -----------------------------

async function generateECDH(): Promise<CryptoKeyPair> {
  return subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    ["deriveBits"]
  );
}

async function generateIdentityKey(): Promise<CryptoKeyPair> {
  return subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"]
  );
}

async function deriveSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  return subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256
  );
}

async function hkdfToAesKey(sharedSecret: ArrayBuffer): Promise<CryptoKey> {
  const secret = await subtle.importKey("raw", sharedSecret, "HKDF", false, [
    "deriveKey",
  ]);

  const info = new TextEncoder().encode("MITM-DEMO-HKDF");
  const salt = new Uint8Array(16); // zeros

  return subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info,
    },
    secret,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptAesGcm(
  key: CryptoKey,
  plaintext: string
): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(plaintext);

  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return { iv, ciphertext };
}

async function decryptAesGcm(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: ArrayBuffer
): Promise<string> {
  const plaintext = await subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(plaintext);
}

function abToB64(buf: ArrayBuffer | Uint8Array): string {
  const u8 = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  return Buffer.from(u8).toString("base64");
}

function b64ToAb(b64: string): ArrayBuffer {
  return Uint8Array.from(Buffer.from(b64, "base64")).buffer;
}

// -----------------------------
// Sign / Verify (identity keys)
// -----------------------------

async function signData(data: ArrayBuffer, privateKey: CryptoKey) {
  return subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    data
  );
}

async function verifyData(
  data: ArrayBuffer,
  signature: ArrayBuffer,
  publicKey: CryptoKey
) {
  return subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    signature,
    data
  );
}

// -----------------------------
// 1) Vulnerable DH (no signatures) — MITM SUCCESS
// -----------------------------

async function runVulnerableDhMitm() {
  console.log("========================================");
  console.log("1) Vulnerable DH (NO signatures) — MITM SHOULD SUCCEED");
  console.log("========================================\n");

  // Honest client & server ECDH keypairs
  const clientDh = await generateECDH();
  const serverDh = await generateECDH();

  // Attacker generates TWO ECDH pairs:
  // one for talking to client, one for talking to server
  const attackerForClient = await generateECDH();
  const attackerForServer = await generateECDH();

  // Export public keys (raw)
  const clientPubRaw = await subtle.exportKey("raw", clientDh.publicKey);
  const serverPubRaw = await subtle.exportKey("raw", serverDh.publicKey);
  const mClientPubRaw = await subtle.exportKey("raw", attackerForClient.publicKey);
  const mServerPubRaw = await subtle.exportKey("raw", attackerForServer.publicKey);

  console.log("Client sends pub C to Server, but MITM intercepts.");
  console.log("Server sends pub S to Client, but MITM intercepts.\n");

  // --- MITM behaviour ---
  // Instead of letting Client and Server see each other's real keys:
  // - Server receives M_server_pub instead of C
  // - Client receives M_client_pub instead of S

  // What each party *thinks* it is using
  const seenByServer = mServerPubRaw;      // server thinks this is client pub
  const seenByClient = mClientPubRaw;      // client thinks this is server pub

  // Derive secrets for each party
  const clientViewSecret = await deriveSharedSecret(
    clientDh.privateKey,
    await subtle.importKey("raw", seenByClient, { name: "ECDH", namedCurve: "P-256" }, true, [])
  );
  const serverViewSecret = await deriveSharedSecret(
    serverDh.privateKey,
    await subtle.importKey("raw", seenByServer, { name: "ECDH", namedCurve: "P-256" }, true, [])
  );

  // Attacker derives BOTH:
  const attackerSecretWithClient = await deriveSharedSecret(
    attackerForClient.privateKey,
    await subtle.importKey("raw", clientPubRaw, { name: "ECDH", namedCurve: "P-256" }, true, [])
  );

  const attackerSecretWithServer = await deriveSharedSecret(
    attackerForServer.privateKey,
    await subtle.importKey("raw", serverPubRaw, { name: "ECDH", namedCurve: "P-256" }, true, [])
  );

  console.log("Client's derived secret (base64):", abToB64(clientViewSecret));
  console.log("Server's derived secret (base64):", abToB64(serverViewSecret));
  console.log("Attacker's secret with CLIENT (base64):", abToB64(attackerSecretWithClient));
  console.log("Attacker's secret with SERVER (base64):", abToB64(attackerSecretWithServer));
  console.log("\n⛔ Client and Server DO NOT share the same key.");
  console.log("✅ But Attacker shares a key with BOTH ends.\n");

  const clientKey = await hkdfToAesKey(clientViewSecret);
  const serverKey = await hkdfToAesKey(serverViewSecret);
  const attackerKeyWithClient = await hkdfToAesKey(attackerSecretWithClient);
  const attackerKeyWithServer = await hkdfToAesKey(attackerSecretWithServer);

  // Client "sends" encrypted message to server, but MITM intercepts
  const secretMessage = "Hello Server, this is a TOP SECRET message.";
  const { iv, ciphertext } = await encryptAesGcm(clientKey, secretMessage);

  console.log("Client -> (encrypted) -> ??? -> Server");
  console.log("Ciphertext (base64):", abToB64(ciphertext), "\n");

  // MITM decrypts using key with client
  const attackerDecrypted = await decryptAesGcm(attackerKeyWithClient, iv, ciphertext);
  console.log("🕵️ Attacker decrypts message from client:");
  console.log("   ", attackerDecrypted, "\n");

  // MITM can then re-encrypt to server using attacker's key with server
  const { iv: iv2, ciphertext: ct2 } = await encryptAesGcm(
    attackerKeyWithServer,
    secretMessage
  );

  const serverDecrypted = await decryptAesGcm(serverKey, iv2, ct2);
  console.log("Server finally decrypts (after MITM re-encryption):");
  console.log("   ", serverDecrypted, "\n");

  console.log("✅ DEMO: In vulnerable DH (no signatures), MITM FULLY READS & RELAYS MESSAGES.\n");
}

// -----------------------------
// 2) Signed ECDH — MITM FAILS
// -----------------------------

async function runSignedDhMitm() {
  console.log("========================================");
  console.log("2) Signed ECDH (with identity keys) — MITM SHOULD FAIL");
  console.log("========================================\n");

  // Identity keys
  const clientIdKeys = await generateIdentityKey();
  const serverIdKeys = await generateIdentityKey();

  // Honest ephemeral ECDH
  const clientDh = await generateECDH();
  const serverDh = await generateECDH();

  // Attacker's ephemeral
  const attackerDh = await generateECDH();

  const clientPubRaw = await subtle.exportKey("raw", clientDh.publicKey);
  const serverPubRaw = await subtle.exportKey("raw", serverDh.publicKey);
  const attackerPubRaw = await subtle.exportKey("raw", attackerDh.publicKey);

  // Client signs its ephemeral key
  const clientSig = await signData(clientPubRaw, clientIdKeys.privateKey);

  // MITM intercepts and tries to MODIFY client's ephemeral key to attacker's
  console.log("MITM intercepts Client -> Server handshake.");
  console.log("MITM attempts to swap client's public key with its own.\n");

  const tamperedPub = attackerPubRaw; // attacker tries to send this instead
  const signatureToSend = clientSig; // BUT still uses client's signature

  // Server verifies signature over the received public key (which was tampered)
  const ok = await verifyData(tamperedPub, signatureToSend, clientIdKeys.publicKey);

  console.log("Server verifying signature on tampered key...");
  console.log("Signature valid? ", ok, "\n");

  if (!ok) {
    console.log("✅ As expected, verification FAILED.");
    console.log("✅ MITM cannot replace the key without breaking the signature.");
    console.log("✅ The handshake is aborted — attack prevented.\n");
    return;
  }

  console.log("⚠ If this prints, something is wrong — MITM should NOT succeed here.\n");
}

// -----------------------------
// Run both demos
// -----------------------------

(async () => {
  await runVulnerableDhMitm();
  await runSignedDhMitm();
})();
