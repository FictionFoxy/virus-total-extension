import { Controller, Post, Body, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { VirusTotalService } from './virustotal.service';
import { ScanUrlDto } from './dto/scan-url.dto';
import { ApiResponseDto, ScanResultDto } from './dto/scan-result.dto';

@Controller('api/virustotal')
export class VirusTotalController {
  private readonly logger = new Logger(VirusTotalController.name);

  constructor(private readonly virusTotalService: VirusTotalService) {}

  @Post('scan')
  async scanUrl(@Body() scanUrlDto: ScanUrlDto): Promise<ApiResponseDto<ScanResultDto>> {
    try {
      this.logger.log(`Received scan request for URL: ${scanUrlDto.url}`);
      
      const result = await this.virusTotalService.scanUrl(scanUrlDto.url);
      
      return {
        success: true,
        data: result,
        message: `URL scan completed: ${result.safe ? 'SAFE' : 'UNSAFE'}`,
      };
    } catch (error) {
      this.logger.error(`Error scanning URL ${scanUrlDto.url}:`, error);
      
      // Handle specific error types
      if (error.message.includes('HTTP 403')) {
        throw new HttpException(
          {
            success: false,
            error: 'Invalid or missing VirusTotal API key',
            message: 'Please check your VIRUS_TOTAL_API_KEY configuration',
          },
          HttpStatus.FORBIDDEN,
        );
      }
      
      if (error.message.includes('HTTP 429')) {
        throw new HttpException(
          {
            success: false,
            error: 'Rate limit exceeded',
            message: 'Too many requests to VirusTotal API. Please try again later.',
          },
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }
      
      if (error.message.includes('Timed out')) {
        throw new HttpException(
          {
            success: false,
            error: 'Analysis timeout',
            message: 'The URL analysis took too long to complete. Please try again.',
          },
          HttpStatus.REQUEST_TIMEOUT,
        );
      }
      
      // Generic error handling
      throw new HttpException(
        {
          success: false,
          error: 'Scan failed',
          message: error.message || 'An unexpected error occurred during URL scanning',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
