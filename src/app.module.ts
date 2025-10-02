import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { VirusTotalModule } from './virustotal/virustotal.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    VirusTotalModule,
  ],
})
export class AppModule {}
