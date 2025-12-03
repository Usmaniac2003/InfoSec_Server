import { Socket } from 'socket.io';
import { Logger } from '@nestjs/common';

export class SocketLogger {
  private static logger = new Logger('SocketLogger');

  static attach(client: Socket) {
    const originalEmit = client.emit.bind(client);

    // Log outgoing events
    client.emit = (event: string, ...args: any[]) => {
      const user = client.data?.user;

      this.logger.log(
        `📡 OUT Event: ${event} | User: ${user?.email ?? 'anonymous'} | Socket: ${
          client.id
        } | Payload: ${this.format(args[0])}`,
      );
      return originalEmit(event, ...args);
    };

    // Log incoming events
    const originalOn = client.on.bind(client);
    client.on = (event: string, listener: (...args: any[]) => void) => {
      return originalOn(event, (...args) => {
        const user = client.data?.user;

        this.logger.log(
          `📥 IN Event: ${event} | User: ${
            user?.email ?? 'anonymous'
          } | Socket: ${client.id} | Payload: ${this.format(args[0])}`,
        );

        listener(...args);
      });
    };
  }

  private static format(payload: any) {
    if (!payload) return '{}';
    const clean = { ...payload };

    if (clean.ciphertext) clean.ciphertext = '[ENCRYPTED DATA]';
    if (clean.iv) clean.iv = '[HIDDEN IV]';

    return JSON.stringify(clean);
  }
}
