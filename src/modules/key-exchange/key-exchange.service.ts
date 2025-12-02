// src/modules/key-exchange/key-exchange.service.ts

import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import {
  ClientHandshakePayload,
  ServerHandshakeResponse,
  KeyExchangeLog,
  ConfirmHandshakePayload,
  ConfirmHandshakeResponse,
} from './key-exchange.types';

type PendingHandshakeRecord = {
  clientEphRaw: ArrayBuffer;
  serverEphKeyPair: CryptoKeyPair;
  createdAt: number;
};

@Injectable()
export class KeyExchangeService {
  private serverIdentityKeyPair: CryptoKeyPair | null = null;
  private readonly logs: KeyExchangeLog[] = [];

  private readonly replayCache = new Set<string>();
  private readonly pendingHandshakes = new Map<
    string,
    PendingHandshakeRecord
  >();

  constructor() {
    void this.initServerIdentityKeys();
  }

  // ----------------------------------------------------------
  // 1. Generate Server Identity Keys (long-term, ECDSA P-256)
  // ----------------------------------------------------------
  private async initServerIdentityKeys() {
    this.serverIdentityKeyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign', 'verify'],
    );

    this.log('server_identity_init', 'ok');
  }

  private log(event: string, status: string, details?: any) {
    this.logs.push({
      event,
      status,
      details,
      timestamp: Date.now(),
    });
  }

  getLogs() {
    return this.logs;
  }

  // ----------------------------------------------------------
  // 2. Verify Replay-Attack Constraints
  // ----------------------------------------------------------
  private verifyReplayProtection(payload: {
    nonce?: string;
    timestamp?: number;
  }) {
    const nonce = payload.nonce;
    const timestamp = payload.timestamp;

    if (!nonce || !timestamp) {
      this.log('replay_check', 'missing_fields', { nonce, timestamp });
      throw new Error('Missing nonce/timestamp');
    }

    // Reject old timestamps (older than 20 seconds)
    if (Date.now() - timestamp > 20_000) {
      this.log('replay_check', 'timestamp_expired', { timestamp });
      throw new Error('Stale message - possible replay attack');
    }

    // Reject duplicated nonces
    if (this.replayCache.has(nonce)) {
      this.log('replay_check', 'duplicate_nonce', { nonce });
      throw new Error('Duplicate nonce - replay detected');
    }

    this.replayCache.add(nonce);
  }

  // ----------------------------------------------------------
  // 3. Import JWK identity public key
  // ----------------------------------------------------------
  private async importIdentityPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
    if (jwk.kty === 'EC') {
      return crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify'],
      );
    }

    if (jwk.kty === 'RSA') {
      return crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSA-PSS', hash: 'SHA-256' },
        true,
        ['verify'],
      );
    }

    throw new Error('Unsupported JWK type');
  }

  // ----------------------------------------------------------
  // Helper: Convert Node Buffer → ArrayBuffer
  // ----------------------------------------------------------
  private bufferToArrayBuffer(buf: Buffer): ArrayBuffer {
    const ab = new ArrayBuffer(buf.length);
    const view = new Uint8Array(ab);
    view.set(buf);
    return ab;
  }

  private arrayBufferToString(buf: ArrayBuffer): string {
    const view = new Uint8Array(buf);
    return new TextDecoder().decode(view);
  }

  // ----------------------------------------------------------
  // 4. Verify Client Signature
  // ----------------------------------------------------------
  private async verifyClientSignature(
    identityKey: CryptoKey,
    clientEphRaw: ArrayBuffer,
    signature: ArrayBuffer,
  ) {
    const algo =
      identityKey.algorithm.name === 'ECDSA'
        ? { name: 'ECDSA', hash: 'SHA-256' }
        : { name: 'RSA-PSS', saltLength: 32 };

    const ok = await crypto.subtle.verify(
      algo,
      identityKey,
      signature,
      clientEphRaw,
    );

    if (!ok) {
      this.log('signature_verify', 'failed');
      throw new Error('Invalid client signature');
    }

    this.log('signature_verify', 'ok');
  }

  // ----------------------------------------------------------
  // 5. Generate Server Ephemeral ECDH Keys
  // ----------------------------------------------------------
  private async generateServerEcdh(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveBits'],
    );
  }

  // ----------------------------------------------------------
  // 6. Derive Session Key from Shared Secret (HKDF → AES-256-GCM)
  // NOTE: Make sure frontend uses the same HKDF: static salt + same info.
  // ----------------------------------------------------------
  private async deriveSessionKey(
    sharedSecret: ArrayBuffer,
  ): Promise<CryptoKey> {
    const secretKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveKey'],
    );

    const encoder = new TextEncoder();
    const info = encoder.encode('E2EE-Session-Key-Derivation');
    const salt = new Uint8Array(16); // all zeros (static) – must match frontend

    const aesKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt,
        info,
      },
      secretKey,
      {
        name: 'AES-GCM',
        length: 256,
      },
      false,
      ['encrypt', 'decrypt'],
    );

    return aesKey;
  }

  // ----------------------------------------------------------
  // 7. Handle Handshake Initiation (/key-exchange/initiate)
  // ----------------------------------------------------------
  async handleInitiateHandshake(
    payload: ClientHandshakePayload,
  ): Promise<ServerHandshakeResponse> {
    // 1. Replay protection
    this.verifyReplayProtection(payload);

    const { clientEphemeralKey, clientIdentityKey, signature } = payload;

    // 2. Decode base64 strings → Buffers → ArrayBuffers
    const ephBuf = Buffer.from(clientEphemeralKey, 'base64');
    const clientEphRaw = this.bufferToArrayBuffer(ephBuf);

    const sigBufNode = Buffer.from(signature, 'base64');
    const sigBuf = this.bufferToArrayBuffer(sigBufNode);

    // 3. Import identity public key
    const identityPubKey =
      await this.importIdentityPublicKey(clientIdentityKey);

    // 4. Verify the signature
    await this.verifyClientSignature(identityPubKey, clientEphRaw, sigBuf);

    // 5. Generate server ephemeral ECDH keypair
    const serverEph = await this.generateServerEcdh();
    const serverEphRaw = await crypto.subtle.exportKey(
      'raw',
      serverEph.publicKey,
    );

    // 6. Sign server ephemeral public key with server identity private key
    const algo =
      this.serverIdentityKeyPair!.privateKey.algorithm.name === 'ECDSA'
        ? { name: 'ECDSA', hash: 'SHA-256' }
        : { name: 'RSA-PSS', saltLength: 32 };

    const serverSignature = await crypto.subtle.sign(
      algo,
      this.serverIdentityKeyPair!.privateKey,
      serverEphRaw,
    );

    // 7. Export server identity public key JWK
    const serverIdentityJwk = await crypto.subtle.exportKey(
      'jwk',
      this.serverIdentityKeyPair!.publicKey,
    );

    // 8. Store pending handshake (for confirm step)
    const handshakeId = randomUUID();
    this.pendingHandshakes.set(handshakeId, {
      clientEphRaw,
      serverEphKeyPair: serverEph,
      createdAt: Date.now(),
    });

    this.log('handshake_initiate', 'ok', { handshakeId });

    return {
      handshakeId,
      serverEphemeralKey: Buffer.from(serverEphRaw).toString('base64'),
      serverSignature: Buffer.from(serverSignature).toString('base64'),
      serverIdentityKey: serverIdentityJwk,
    };
  }

  // ----------------------------------------------------------
  // 8. Handle Handshake Confirmation (/key-exchange/confirm)
  // ----------------------------------------------------------
  async handleConfirmHandshake(
    payload: ConfirmHandshakePayload,
  ): Promise<ConfirmHandshakeResponse> {
    // Replay protection
    this.verifyReplayProtection(payload);

    const { handshakeId, iv, confirmationTag } = payload;

    const record = this.pendingHandshakes.get(handshakeId);
    if (!record) {
      this.log('handshake_confirm', 'missing_record', { handshakeId });
      throw new Error('Unknown or expired handshakeId');
    }

    // Optional: expire very old pending handshakes
    if (Date.now() - record.createdAt > 60_000) {
      this.pendingHandshakes.delete(handshakeId);
      this.log('handshake_confirm', 'expired', { handshakeId });
      throw new Error('Handshake expired');
    }

    // Import client ephemeral public key for ECDH
    const clientEphKey = await crypto.subtle.importKey(
      'raw',
      record.clientEphRaw,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      [],
    );

    // Derive shared secret
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: clientEphKey,
      },
      record.serverEphKeyPair.privateKey,
      256,
    );

    // Derive AES-256-GCM session key (HKDF)
    const sessionKey = await this.deriveSessionKey(sharedSecret);

    // Decode IV & ciphertext
    const ivBuf = Buffer.from(iv, 'base64');
    const ivBytes = new Uint8Array(ivBuf);

    const tagBufNode = Buffer.from(confirmationTag, 'base64');
    const tagBuf = this.bufferToArrayBuffer(tagBufNode);

    // Decrypt confirmation
    let plaintext: ArrayBuffer;
    try {
      plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ivBytes,
        },
        sessionKey,
        tagBuf,
      );
    } catch (err) {
      this.log('handshake_confirm', 'decrypt_failed', { handshakeId });
      throw new Error('Failed to decrypt confirmation tag');
    }

    const text = this.arrayBufferToString(plaintext);
    if (text !== 'KEY_CONFIRM') {
      this.log('handshake_confirm', 'invalid_payload', { handshakeId, text });
      throw new Error('Invalid confirmation payload');
    }

    // Success: remove from pending, log ok
    this.pendingHandshakes.delete(handshakeId);
    this.log('handshake_confirm', 'ok', { handshakeId });

    return {
      status: 'ok',
      message: 'Key confirmation successful',
    };
  }
}
