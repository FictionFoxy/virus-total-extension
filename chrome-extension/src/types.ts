// Type definitions for VirusTotal API responses and Chrome extension

export interface AnalysisStats {
  harmless: number;
  malicious: number;
  suspicious: number;
  timeout: number;
  undetected: number;
}

export interface TotalVotes {
  harmless: number;
  malicious: number;
}

export interface ScanResult {
  url: string;
  safe: boolean;
  wasStale: boolean;
  stale_age_human: string;
  last_submitted_ago: string;
  last_analysis_date: string | null;
  last_submission_date: string | null;
  times_submitted: number | null;
  total_votes: TotalVotes;
  last_analysis_stats: AnalysisStats;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface ScanRequest {
  url: string;
}

export interface ChromeMessage {
  action: string;
  url?: string;
  enabled?: boolean;
  data?: any;
}

export interface StoredScanResult {
  url: string;
  result: ScanResult;
  timestamp: string;
}

export interface ExtensionConfig {
  apiEndpoint: string;
  autoScan: boolean;
  showNotifications: boolean;
}

export type NotificationType = 'info' | 'success' | 'warning' | 'error';

export interface NotificationOptions {
  message: string;
  type: NotificationType;
  url: string;
  details?: ScanResult;
  duration?: number;
}
