import { Module } from '@nestjs/common';
import { VirusTotalController } from './virustotal.controller';
import { VirusTotalService } from './virustotal.service';

@Module({
  controllers: [VirusTotalController],
  providers: [VirusTotalService],
  exports: [VirusTotalService],
})
export class VirusTotalModule {}
