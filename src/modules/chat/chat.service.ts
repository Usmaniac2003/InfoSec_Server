import { Injectable } from '@nestjs/common';
import {
  ChatMessage,
  IncomingMessagePayload,
} from '../../types/chat/chat.types';

@Injectable()
export class ChatService {
  formatMessage(payload: IncomingMessagePayload): ChatMessage {
    return {
      id: Date.now(),
      sender: payload.sender,
      type: payload.type,
      text: payload.text,
      file: payload.file,
      time: new Date().toLocaleTimeString(),
    };
  }
}
