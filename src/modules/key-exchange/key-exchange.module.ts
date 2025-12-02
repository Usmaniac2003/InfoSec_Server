import { Module } from '@nestjs/common';
import { KeyExchangeService } from './key-exchange.service';
import { KeyExchangeController } from './key-exchange.controller';

@Module({
  controllers: [KeyExchangeController],
  providers: [KeyExchangeService],
  exports: [KeyExchangeService],
})
export class KeyExchangeModule {}
