export class AnalysisStatsDto {
  harmless: number;
  malicious: number;
  suspicious: number;
  timeout: number;
  undetected: number;
}

export class TotalVotesDto {
  harmless: number;
  malicious: number;
}

export class ScanResultDto {
  url: string;
  safe: boolean;
  wasStale: boolean;
  stale_age_human: string;
  last_submitted_ago: string;
  last_analysis_date: string | null;
  last_submission_date: string | null;
  times_submitted: number | null;
  total_votes: TotalVotesDto;
  last_analysis_stats: AnalysisStatsDto;
}

export class ApiResponseDto<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}
