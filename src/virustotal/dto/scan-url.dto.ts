import { IsUrl, IsNotEmpty } from 'class-validator';

export class ScanUrlDto {
  @IsUrl({}, { message: 'Please provide a valid URL' })
  @IsNotEmpty({ message: 'URL is required' })
  url: string;
}
