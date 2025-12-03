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

  // ⭐ Shared group key for all clients
  private groupKey: CryptoKey | null = null;
  private groupKeyRaw: ArrayBuffer | null = null;

  constructor() {
    void this.initServerIdentityKeys();
    void this.initGroupKey();
  }

  // ----------------------------------------------------------
  // Group Key (shared AES-256 for group chat)
  // ----------------------------------------------------------
  private async initGroupKey() {
    this.groupKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    this.groupKeyRaw = await crypto.subtle.exportKey('raw', this.groupKey);

    this.log('group_key_init', 'ok');
  }

  // ----------------------------------------------------------
  // Server long-term identity keys
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

  // ----------------------------------------------------------
  // Logging helper
  // ----------------------------------------------------------
  private log(event: string, status: string, details?: any) {
    const entry: KeyExchangeLog = {
      event,
      status,
      details,
      timestamp: Date.now(),
    };

    this.logs.push(entry);
    // Optional: also print to server console
    // eslint-disable-next-line no-console
    console.log('🔐 LOG:', entry);
  }

  getLogs() {
    return this.logs;
  }

  // ----------------------------------------------------------
  // Replay protection
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

    const age = Date.now() - timestamp;
    if (age > 20_000) {
      this.log('replay_check', 'timestamp_expired', { timestamp, age });
      throw new Error('Stale message - possible replay attack');
    }

    if (this.replayCache.has(nonce)) {
      this.log('replay_check', 'duplicate_nonce', { nonce });
      throw new Error('Duplicate nonce - replay detected');
    }

    this.replayCache.add(nonce);
    this.log('replay_check', 'ok', { nonce, age });
  }

  // ----------------------------------------------------------
  // Identity public key import
  // ----------------------------------------------------------
  private async importIdentityPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
    if (jwk.kty === 'EC') {
      const key = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify'],
      );
      this.log('identity_key_import', 'ok', { kty: jwk.kty, alg: 'ECDSA' });
      return key;
    }

    if (jwk.kty === 'RSA') {
      const key = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSA-PSS', hash: 'SHA-256' },
        true,
        ['verify'],
      );
      this.log('identity_key_import', 'ok', { kty: jwk.kty, alg: 'RSA-PSS' });
      return key;
    }

    this.log('identity_key_import', 'failed', { kty: jwk.kty });
    throw new Error('Unsupported JWK type');
  }

  // ----------------------------------------------------------
  // Helpers: buffers
  // ----------------------------------------------------------
  private bufferToArrayBuffer(buf: Buffer): ArrayBuffer {
    const ab = new ArrayBuffer(buf.length);
    const view = new Uint8Array(ab);
    view.set(buf);
    return ab;
  }

  private arrayBufferToString(buf: ArrayBuffer): string {
    return new TextDecoder().decode(new Uint8Array(buf));
  }

  // ----------------------------------------------------------
  // Signature verification
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
  // Server ECDH ephemeral keys
  // ----------------------------------------------------------
  private async generateServerEcdh(): Promise<CryptoKeyPair> {
    const pair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveBits'],
    );

    this.log('server_ephemeral_generated', 'ok');
    return pair;
  }

  // ----------------------------------------------------------
  // Session key derivation (HKDF → AES-256-GCM)
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

    const info = new TextEncoder().encode('E2EE-Session-Key-Derivation');
    const salt = new Uint8Array(16);

    const sessionKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt,
        info,
      },
      secretKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );

    this.log('session_key_derived', 'ok');
    return sessionKey;
  }

  // ----------------------------------------------------------
  // /key-exchange/initiate
  // ----------------------------------------------------------
  async handleInitiateHandshake(
    payload: ClientHandshakePayload,
  ): Promise<ServerHandshakeResponse> {
    this.log('initiate_received', 'ok');
    this.verifyReplayProtection(payload);

    // Decode client ephemeral key + signature
    const ephBuf = Buffer.from(payload.clientEphemeralKey, 'base64');
    const clientEphRaw = this.bufferToArrayBuffer(ephBuf);

    const sigBuf = this.bufferToArrayBuffer(
      Buffer.from(payload.signature, 'base64'),
    );

    // Import identity key
    const identityPub = await this.importIdentityPublicKey(
      payload.clientIdentityKey,
    );

    // Verify signature
    await this.verifyClientSignature(identityPub, clientEphRaw, sigBuf);

    // Generate server ephemeral ECDH
    const serverEph = await this.generateServerEcdh();
    const serverEphRaw = await crypto.subtle.exportKey(
      'raw',
      serverEph.publicKey,
    );

    // Sign server ephemeral public key
    const signAlgo =
      this.serverIdentityKeyPair!.privateKey.algorithm.name === 'ECDSA'
        ? { name: 'ECDSA', hash: 'SHA-256' }
        : { name: 'RSA-PSS', saltLength: 32 };

    const serverSig = await crypto.subtle.sign(
      signAlgo,
      this.serverIdentityKeyPair!.privateKey,
      serverEphRaw,
    );

    this.log('server_ephemeral_signed', 'ok');

    const handshakeId = randomUUID();

    this.pendingHandshakes.set(handshakeId, {
      clientEphRaw,
      serverEphKeyPair: serverEph,
      createdAt: Date.now(),
    });

    this.log('handshake_stored', 'ok', { handshakeId });

    return {
      handshakeId,
      serverEphemeralKey: Buffer.from(serverEphRaw).toString('base64'),
      serverSignature: Buffer.from(serverSig).toString('base64'),
      serverIdentityKey: await crypto.subtle.exportKey(
        'jwk',
        this.serverIdentityKeyPair!.publicKey,
      ),
    };
  }

  // ----------------------------------------------------------
  // /key-exchange/confirm
  // ----------------------------------------------------------
  async handleConfirmHandshake(
    payload: ConfirmHandshakePayload,
  ): Promise<ConfirmHandshakeResponse> {
    this.log('confirm_received', 'ok', { handshakeId: payload.handshakeId });
    this.verifyReplayProtection(payload);

    const record = this.pendingHandshakes.get(payload.handshakeId);
    if (!record) {
      this.log('handshake_confirm', 'missing_record', {
        handshakeId: payload.handshakeId,
      });
      throw new Error('Unknown handshakeId');
    }

    const clientPubKey = await crypto.subtle.importKey(
      'raw',
      record.clientEphRaw,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      [],
    );

    // Derive shared secret + session key
    const sharedSecret = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: clientPubKey },
      record.serverEphKeyPair.privateKey,
      256,
    );

    const sessionKey = await this.deriveSessionKey(sharedSecret);

    // Decrypt confirmation message
    const iv = new Uint8Array(Buffer.from(payload.iv, 'base64'));
    const ciphertext = Buffer.from(payload.confirmationTag, 'base64');

    let decrypted: ArrayBuffer;
    try {
      decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        sessionKey,
        ciphertext,
      );
    } catch (err) {
      this.log('confirmation_decrypt', 'failed', {
        handshakeId: payload.handshakeId,
      });
      throw new Error('Failed to decrypt confirmation');
    }

    const text = this.arrayBufferToString(decrypted);

    if (text !== 'KEY_CONFIRM') {
      this.log('confirmation_payload', 'invalid', {
        handshakeId: payload.handshakeId,
        text,
      });
      throw new Error('Invalid confirm payload');
    }

    this.log('confirmation_decrypt', 'ok', {
      handshakeId: payload.handshakeId,
    });

    // Encrypt groupKey for this user
    const groupIv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedGroupKey = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: groupIv },
      sessionKey,
      this.groupKeyRaw!,
    );

    this.log('group_key_encrypted', 'ok', { handshakeId: payload.handshakeId });

    // Optionally cleanup pending record
    this.pendingHandshakes.delete(payload.handshakeId);
    this.log('handshake_confirm', 'ok', { handshakeId: payload.handshakeId });

    return {
      status: 'ok',
      encryptedGroupKey: Buffer.from(encryptedGroupKey).toString('base64'),
      groupIv: Buffer.from(groupIv).toString('base64'),
    };
  }

  // ----------------------------------------------------------
  // Vulnerable Key Exchange
  // ----------------------------------------------------------

  async vulnerableHandshake(payload: any) {
    const clientPubRaw = Buffer.from(payload.clientEphemeralKey, 'base64');

    // Generate server DH ephemerals
    const serverEph = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    );

    const serverPubRaw = await crypto.subtle.exportKey(
      'raw',
      serverEph.publicKey,
    );

    return {
      serverEphemeralKey: Buffer.from(serverPubRaw).toString('base64'),
      note: 'VULNERABLE DH: UNSIGNED, UNAUTHENTICATED, MITM POSSIBLE',
    };
  }
}
