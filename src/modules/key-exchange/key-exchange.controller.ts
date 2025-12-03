// src/modules/key-exchange/key-exchange.controller.ts

import { Body, Controller, Get, Post } from '@nestjs/common';
import { KeyExchangeService } from './key-exchange.service';
import * as keyExchangeTypes from './key-exchange.types';

@Controller('key-exchange')
export class KeyExchangeController {
  constructor(private readonly keyService: KeyExchangeService) {}

  @Post('vulnerable-initiate')
  async vulnerableInit(@Body() payload: any) {
    return this.keyService.vulnerableHandshake(payload);
  }

  @Post('initiate')
  async initiate(@Body() payload: keyExchangeTypes.ClientHandshakePayload) {
    return this.keyService.handleInitiateHandshake(payload);
  }

  @Post('confirm')
  async confirm(@Body() payload: keyExchangeTypes.ConfirmHandshakePayload) {
    return this.keyService.handleConfirmHandshake(payload);
  }

  @Get('logs')
  getLogs() {
    return this.keyService.getLogs();
  }
}
