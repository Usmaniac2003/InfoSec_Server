// src/modules/key-exchange/key-exchange.types.ts

export interface ClientHandshakePayload {
  clientEphemeralKey: string; // base64 raw public key
  clientIdentityKey: JsonWebKey; // identity public key (ECDSA P-256 or RSA)
  signature: string; // base64 signature of ephemeral key
  nonce?: string;
  timestamp?: number;
}

export interface ServerHandshakeResponse {
  handshakeId: string; // NEW: link to pending handshake
  serverEphemeralKey: string; // base64 raw ephemeral public key
  serverSignature: string; // signature of server ephemeral key
  serverIdentityKey: JsonWebKey; // server identity key JWK
}

export interface ConfirmHandshakePayload {
  handshakeId: string;
  iv: string; // base64 IV used by client for AES-GCM
  confirmationTag: string; // base64 ciphertext of e.g. "KEY_CONFIRM"
  nonce?: string;
  timestamp?: number;
}

export interface ConfirmHandshakeResponse {
  status: string;
  message?: string;

  // ⭐ NEW FIELDS for secure group key delivery
  encryptedGroupKey: string; // base64 AES-GCM encrypted group key
  groupIv: string; // base64 IV used to encrypt the group key
}

export interface KeyExchangeLog {
  event: string;
  status: string;
  details?: any;
  timestamp: number;
}
