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

      console.log(`✅ User connected: ${decoded.email}`);
    } catch {
      client.disconnect();
    }
  }

  handleDisconnect(): void {
    console.log('❌ User disconnected');
  }

  @SubscribeMessage('send_message')
  handleMessage(
    @MessageBody() payload: any,
    @ConnectedSocket() client: Socket,
  ) {
    const user = client.data.user;

    const message = {
      id: Date.now(),
      senderId: payload.senderId ?? user?.id,
      sender: payload.sender ?? user?.email,
      type: 'text',
      iv: payload.iv,
      ciphertext: payload.ciphertext,
      time: new Date().toLocaleTimeString(),
    };

    this.server.emit('receive_message', message);
  }

  @SubscribeMessage('send_file')
  handleFile(@MessageBody() payload: any, @ConnectedSocket() client: Socket) {
    const user = client.data.user;

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
