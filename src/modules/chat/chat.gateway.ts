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
import * as chatTypes from '../../types/chat/chat.types';

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

  // ---------------------------
  // SOCKET CONNECTION + AUTH
  // ---------------------------
  handleConnection(client: Socket): void {
    try {
      const token = client.handshake.auth?.token as string | undefined;

      if (!token) {
        console.log('❌ No token provided. Disconnecting.');
        client.disconnect();
        return;
      }

      // Validate JWT and cast to proper type
      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET || 'default_jwt_secret',
      ) as jwt.JwtPayload;

      client.data.user = decoded;

      console.log(`✅ User connected: ${decoded.email}`);
    } catch {
      console.log('❌ Invalid token. Disconnecting client.');
      client.disconnect();
    }
  }

  handleDisconnect(): void {
    console.log('❌ User disconnected');
  }

  // ---------------------------
  // TEXT MESSAGE
  // ---------------------------
  @SubscribeMessage('send_message')
  handleMessage(
    @MessageBody() payload: chatTypes.IncomingMessagePayload,
    @ConnectedSocket() client: Socket,
  ): void {
    const user = client.data.user as { email?: string } | undefined;

    const message = this.chatService.formatMessage({
      ...payload,
      sender: payload.sender ?? user?.email ?? 'Unknown',
      type: 'text',
    });

    this.server.emit('receive_message', message);
  }

  // ---------------------------
  // FILE MESSAGE
  // ---------------------------
  @SubscribeMessage('send_file')
  handleFile(
    @MessageBody() payload: chatTypes.IncomingMessagePayload,
    @ConnectedSocket() client: Socket,
  ) {
    const user = client.data.user;

    const message = this.chatService.formatMessage({
      sender: payload.sender ?? user.email,
      type: 'file',
      file: payload.file as chatTypes.FilePayload,
    });

    this.server.emit('receive_message', message);
  }
}
