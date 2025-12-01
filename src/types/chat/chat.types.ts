interface ChatMessage {
  id: number;
  sender: string;
  type: 'text' | 'file';
  text?: string;
  file?: any;
  time: string;
}

interface IncomingMessagePayload {
  sender: string;
  type: 'text' | 'file';
  text?: string;
  file?: any;
}

interface JwtPayload {
  sub: number; // your user ID
  email: string; // your user's email
  iat?: number;
  exp?: number;
}

interface FilePayload {
  name: string;
  size: number;
  type: string;
  base64: string;
}

export type { ChatMessage, IncomingMessagePayload, JwtPayload, FilePayload };
