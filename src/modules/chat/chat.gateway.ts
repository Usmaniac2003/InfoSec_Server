import {
  WebSocketGateway,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
  OnGatewayInit,
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketServer,
} from '@nestjs/websockets';

import { Server, Socket } from 'socket.io';
import * as jwt from 'jsonwebtoken';
import { ChatService } from './chat.service';

@WebSocketGateway({
  cors: {
    origin: [
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'http://192.168.209.1:3000',
    ],
    credentials: false,
  },
})
export class ChatGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect
{
  @WebSocketServer()
  private readonly server!: Server;

  constructor(private readonly chatService: ChatService) {}

  afterInit(): void {
    console.log('🚀 ChatGateway initialized');
  }

  handleConnection(client: Socket): void {
    try {
      const token = client.handshake.auth?.token;

      if (!token) {
        client.disconnect();
        return;
      }

      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET || 'default_jwt_secret',
      ) as jwt.JwtPayload;

      client.data.user = decoded;

      console.log(`\n==============================`);
      console.log(`✅ User connected: ${decoded.email}`);
      console.log(`==============================\n`);
    } catch {
      client.disconnect();
    }
  }

  handleDisconnect(): void {
    console.log('❌ User disconnected');
  }

  // -------------------------------------------------------------------
  // 🔹 HELPER LOGGER (prints encrypted vs plaintext message)
  // -------------------------------------------------------------------
  private logIncomingMessage(type: string, sender: any, payload: any) {
    const isEncrypted = payload.iv && payload.ciphertext;

    console.log(`\n----- 📩 Incoming ${type.toUpperCase()} Message -----`);
    console.log(
      `👤 Sender: ${sender?.email ?? sender?.firstName ?? 'Unknown'}`,
    );
    console.log(
      `🔐 Encryption: ${isEncrypted ? 'ENCRYPTED' : 'PLAINTEXT (MITM vulnerable)'}`,
    );

    if (isEncrypted) {
      console.log(`🔑 IV (base64): ${payload.iv}`);
      console.log(`🧩 Ciphertext length: ${payload.ciphertext.length}`);
      console.log(
        `📦 Ciphertext (preview): ${payload.ciphertext.substring(0, 40)}...`,
      );
    } else {
      console.log(
        `📝 Plaintext message: ${payload.text ?? '[NO TEXT FIELD PROVIDED]'}`,
      );
    }

    if (type === 'file') {
      console.log(`📁 File Name: ${payload.fileName}`);
      console.log(`📦 Mime Type: ${payload.mimeType}`);
      console.log(`📏 Size: ${payload.size} bytes`);
    }

    console.log(`----------------------------------------\n`);
  }

  // -------------------------------------------------------------------
  // TEXT MESSAGE
  // -------------------------------------------------------------------
  @SubscribeMessage('send_message')
  handleMessage(
    @MessageBody() payload: any,
    @ConnectedSocket() client: Socket,
  ) {
    const user = client.data.user;
    const MITM = true;
    // 🔹 LOG HERE
    this.logIncomingMessage('text', user, payload);

    const message = {
      id: Date.now(),
      senderId: payload.senderId ?? user?.id,
      sender: payload.sender ?? user?.email,
      type: 'text',

      // 🔥 If encrypted → forward iv + ciphertext
      // 🔥 If plaintext → forward text
      iv: MITM ? payload.iv : null,
      ciphertext: MITM ? payload.ciphertext : null,
      text: !MITM ? payload.text : null,

      time: new Date().toLocaleTimeString(),
    };

    this.server.emit('receive_message', message);
  }

  // -------------------------------------------------------------------
  // FILE MESSAGE
  // -------------------------------------------------------------------
  @SubscribeMessage('send_file')
  handleFile(@MessageBody() payload: any, @ConnectedSocket() client: Socket) {
    const user = client.data.user;

    // 🔹 LOG HERE
    this.logIncomingMessage('file', user, payload);

    const message = {
      id: Date.now(),
      senderId: payload.senderId ?? user?.id,
      sender: payload.sender ?? user?.email,
      type: 'file',
      iv: payload.iv,
      ciphertext: payload.ciphertext,
      fileName: payload.fileName,
      mimeType: payload.mimeType,
      size: payload.size,
      time: new Date().toLocaleTimeString(),
    };

    this.server.emit('receive_message', message);
  }
}
