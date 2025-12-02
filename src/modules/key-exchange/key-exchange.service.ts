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

  // ⭐ NEW: Shared group key for all clients
  private groupKey: CryptoKey | null = null;
  private groupKeyRaw: ArrayBuffer | null = null;

  constructor() {
    void this.initServerIdentityKeys();
    void this.initGroupKey();
  }

  private async initGroupKey() {
    this.groupKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    this.groupKeyRaw = await crypto.subtle.exportKey('raw', this.groupKey);

    console.log('🔑 Group key generated');
  }

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

  private verifyReplayProtection(payload: {
    nonce?: string;
    timestamp?: number;
  }) {
    const nonce = payload.nonce;
    const timestamp = payload.timestamp;

    if (!nonce || !timestamp) {
      throw new Error('Missing nonce/timestamp');
    }

    if (Date.now() - timestamp > 20_000) {
      throw new Error('Stale message - possible replay attack');
    }

    if (this.replayCache.has(nonce)) {
      throw new Error('Duplicate nonce - replay detected');
    }

    this.replayCache.add(nonce);
  }

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

  private bufferToArrayBuffer(buf: Buffer): ArrayBuffer {
    const ab = new ArrayBuffer(buf.length);
    const view = new Uint8Array(ab);
    view.set(buf);
    return ab;
  }

  private arrayBufferToString(buf: ArrayBuffer): string {
    return new TextDecoder().decode(new Uint8Array(buf));
  }

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
      throw new Error('Invalid client signature');
    }
  }

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

    return crypto.subtle.deriveKey(
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
  }

  async handleInitiateHandshake(
    payload: ClientHandshakePayload,
  ): Promise<ServerHandshakeResponse> {
    this.verifyReplayProtection(payload);

    const ephBuf = Buffer.from(payload.clientEphemeralKey, 'base64');
    const clientEphRaw = this.bufferToArrayBuffer(ephBuf);

    const sigBuf = this.bufferToArrayBuffer(
      Buffer.from(payload.signature, 'base64'),
    );

    const identityPub = await this.importIdentityPublicKey(
      payload.clientIdentityKey,
    );

    await this.verifyClientSignature(identityPub, clientEphRaw, sigBuf);

    const serverEph = await this.generateServerEcdh();
    const serverEphRaw = await crypto.subtle.exportKey(
      'raw',
      serverEph.publicKey,
    );

    const serverSig = await crypto.subtle.sign(
      this.serverIdentityKeyPair!.privateKey.algorithm.name === 'ECDSA'
        ? { name: 'ECDSA', hash: 'SHA-256' }
        : { name: 'RSA-PSS', saltLength: 32 },
      this.serverIdentityKeyPair!.privateKey,
      serverEphRaw,
    );

    const handshakeId = randomUUID();

    this.pendingHandshakes.set(handshakeId, {
      clientEphRaw,
      serverEphKeyPair: serverEph,
      createdAt: Date.now(),
    });

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

  async handleConfirmHandshake(
    payload: ConfirmHandshakePayload,
  ): Promise<ConfirmHandshakeResponse> {
    this.verifyReplayProtection(payload);

    const record = this.pendingHandshakes.get(payload.handshakeId);
    if (!record) throw new Error('Unknown handshakeId');

    const clientPubKey = await crypto.subtle.importKey(
      'raw',
      record.clientEphRaw,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      [],
    );

    const sharedSecret = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: clientPubKey },
      record.serverEphKeyPair.privateKey,
      256,
    );

    const sessionKey = await this.deriveSessionKey(sharedSecret);

    const iv = new Uint8Array(Buffer.from(payload.iv, 'base64'));
    const ciphertext = Buffer.from(payload.confirmationTag, 'base64');

    let decrypted;
    try {
      decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        sessionKey,
        ciphertext,
      );
    } catch {
      throw new Error('Failed to decrypt confirmation');
    }

    const text = this.arrayBufferToString(decrypted);

    if (text !== 'KEY_CONFIRM') throw new Error('Invalid confirm payload');

    // ⭐ Encrypt groupKey for this user
    const groupIv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedGroupKey = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: groupIv },
      sessionKey,
      this.groupKeyRaw!,
    );

    return {
      status: 'ok',
      encryptedGroupKey: Buffer.from(encryptedGroupKey).toString('base64'),
      groupIv: Buffer.from(groupIv).toString('base64'),
    };
  }
}
