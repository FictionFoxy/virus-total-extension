import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Type definitions
interface AnalysisStats {
  harmless: number;
  malicious: number;
  suspicious: number;
  timeout: number;
  undetected: number;
}

interface TotalVotes {
  harmless: number;
  malicious: number;
}

interface UrlReportAttributes {
  last_analysis_date?: number;
  last_submission_date?: number;
  times_submitted?: number;
  last_analysis_stats?: AnalysisStats;
  total_votes?: TotalVotes;
}

interface UrlReportData {
  id: string;
  type: string;
  attributes: UrlReportAttributes;
}

interface UrlReport {
  data: UrlReportData;
}

interface AnalysisData {
  id: string;
  type: string;
  attributes: {
    status: string;
    date?: number;
  };
}

interface AnalysisResponse {
  data: AnalysisData;
}

interface SubmitUrlResponse {
  data: {
    id: string;
    type: string;
  };
}

export interface ScanSummary {
  url: string;
  wasStale: boolean;
  stale_age_human: string;
  last_submitted_ago: string;
  last_analysis_date: string | null;
  last_submission_date: string | null;
  times_submitted: number | null;
  total_votes: TotalVotes;
  last_analysis_stats: AnalysisStats;
  safe: boolean;
}

interface WaitOptions {
  intervalMs?: number;
  timeoutMs?: number;
}

@Injectable()
export class VirusTotalService {
  private readonly logger = new Logger(VirusTotalService.name);
  private readonly VT_BASE = 'https://www.virustotal.com/api/v3';
  private readonly apiKey: string;

  constructor(private configService: ConfigService) {
    this.apiKey = this.configService.get<string>('VIRUS_TOTAL_API_KEY');
    if (!this.apiKey) {
      throw new Error('VIRUS_TOTAL_API_KEY is required in environment variables');
    }
  }

  // Simple sleep util
  private sleep(ms: number): Promise<void> {
    return new Promise((res) => setTimeout(res, ms));
  }

  // Base64url encode (no padding)
  private b64url(input: string): string {
    try {
      // Node.js path
      return Buffer.from(input, 'utf8')
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    } catch (_) {
      // Fallback path
      const bytes = new TextEncoder().encode(input);
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
  }

  private toIso(tsSec?: number): string | null {
    if (!tsSec) return null;
    return new Date(tsSec * 1000).toISOString();
  }

  private humanizeDuration(ms: number | null): string {
    if (ms == null || ms < 0) return 'unknown';
    const sec = Math.floor(ms / 1000);
    const mins = Math.floor(sec / 60);
    const hours = Math.floor(mins / 60);
    const days = Math.floor(hours / 24);
    const months = Math.floor(days / 30);
    if (months >= 1) return `${months} month${months > 1 ? 's' : ''} ${days % 30}d`;
    if (days >= 1) return `${days}d ${hours % 24}h`;
    if (hours >= 1) return `${hours}h ${mins % 60}m`;
    if (mins >= 1) return `${mins}m`;
    return `${sec}s`;
  }

  // Basic fetch with helpful errors
  private async fetchJson<T>(url: string, opts: RequestInit = {}): Promise<T | null> {
    try {
      const res = await fetch(url, opts);
      if (res.ok) return res.json() as Promise<T>;
      if (res.status === 404) return null;
      const text = await res.text();
      throw new Error(`HTTP ${res.status}: ${text || res.statusText}`);
    } catch (error) {
      this.logger.error(`Fetch error for ${url}:`, error);
      throw error;
    }
  }

  // Get current URL report (if any)
  private async getUrlReport(urlStr: string): Promise<UrlReport | null> {
    const id = this.b64url(urlStr);
    const json = await this.fetchJson<UrlReport>(`${this.VT_BASE}/urls/${id}`, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        'x-apikey': this.apiKey,
      },
    });
    return json;
  }

  // Submit URL for analysis
  private async submitUrl(urlStr: string): Promise<string> {
    const body = new URLSearchParams({ url: urlStr });
    const json = await this.fetchJson<SubmitUrlResponse>(`${this.VT_BASE}/urls`, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
        'x-apikey': this.apiKey,
      },
      body,
    });
    if (!json?.data?.id) throw new Error('No analysis ID returned from VirusTotal.');
    return json.data.id;
  }

  // Wait until analysis completes
  private async waitForAnalysis(
    analysisId: string,
    { intervalMs = 3000, timeoutMs = 180000 }: WaitOptions = {}
  ): Promise<AnalysisResponse> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const json = await this.fetchJson<AnalysisResponse>(`${this.VT_BASE}/analyses/${analysisId}`, {
        method: 'GET',
        headers: { accept: 'application/json', 'x-apikey': this.apiKey },
      });
      const status = json?.data?.attributes?.status;
      if (status === 'completed') return json!;
      if (status && status !== 'queued' && status !== 'running') {
        throw new Error(`Unexpected analysis status: ${status}`);
      }
      await this.sleep(intervalMs);
    }
    throw new Error('Timed out waiting for analysis to complete.');
  }

  // Compute safe/unsafe + summary
  private summarize(urlStr: string, initialReport: UrlReport | null, finalReport: UrlReport): ScanSummary {
    const now = Date.now();

    const initialAttr = initialReport?.data?.attributes || null;
    const finalAttr = finalReport?.data?.attributes || {};

    const lastAnalysisStats: AnalysisStats = finalAttr.last_analysis_stats || {
      harmless: 0,
      malicious: 0,
      suspicious: 0,
      timeout: 0,
      undetected: 0,
    };

    const totalVotes: TotalVotes = finalAttr.total_votes || { harmless: 0, malicious: 0 };

    // "Unsafe" if any malicious or suspicious detections from security engines
    // Community votes are less reliable and should not override engine results
    const unsafe = (lastAnalysisStats.malicious || 0) + (lastAnalysisStats.suspicious || 0) > 0;

    // Staleness check BEFORE this scan (based on previous last_analysis_date)
    let wasStale = false;
    let staleAgeMs: number | null = null;
    let lastSubmittedAgoMs: number | null = null;

    if (initialAttr?.last_analysis_date) {
      staleAgeMs = now - initialAttr.last_analysis_date * 1000;
      wasStale = staleAgeMs > 30 * 24 * 60 * 60 * 1000; // > 30 days
    }
    if (initialAttr?.last_submission_date) {
      lastSubmittedAgoMs = now - initialAttr.last_submission_date * 1000;
    }

    return {
      url: urlStr,
      wasStale,
      stale_age_human: wasStale ? this.humanizeDuration(staleAgeMs) : 'fresh',
      last_submitted_ago: lastSubmittedAgoMs != null ? this.humanizeDuration(lastSubmittedAgoMs) : 'unknown',
      last_analysis_date: this.toIso(finalAttr.last_analysis_date),
      last_submission_date: this.toIso(finalAttr.last_submission_date),
      times_submitted: finalAttr.times_submitted ?? null,
      total_votes: {
        harmless: totalVotes.harmless || 0,
        malicious: totalVotes.malicious || 0,
      },
      last_analysis_stats: {
        harmless: lastAnalysisStats.harmless || 0,
        malicious: lastAnalysisStats.malicious || 0,
        suspicious: lastAnalysisStats.suspicious || 0,
        timeout: lastAnalysisStats.timeout || 0,
        undetected: lastAnalysisStats.undetected || 0,
      },
      safe: !unsafe,
    };
  }

  // Main scanning method
  async scanUrl(urlStr: string): Promise<ScanSummary> {
    this.logger.log(`Starting scan for URL: ${urlStr}`);

    try {
      // 1) Fetch current report (to determine staleness before re-scan)
      const initialReport = await this.getUrlReport(urlStr);
      this.logger.log(`Initial report fetched: ${initialReport ? 'found' : 'not found'}`);

      // 2) Submit the URL for analysis
      const analysisId = await this.submitUrl(urlStr);
      this.logger.log(`URL submitted for analysis: ${analysisId}`);

      // 3) Wait until the analysis completes
      await this.waitForAnalysis(analysisId);
      this.logger.log(`Analysis completed for: ${analysisId}`);

      // 4) Fetch the final URL report
      const finalReport = await this.getUrlReport(urlStr);
      if (!finalReport) throw new Error('Final report not found after analysis.');

      // 5) Build summary
      const summary = this.summarize(urlStr, initialReport, finalReport);
      this.logger.log(`Scan completed for ${urlStr}: ${summary.safe ? 'SAFE' : 'UNSAFE'}`);

      return summary;
    } catch (error) {
      this.logger.error(`Error scanning URL ${urlStr}:`, error);
      throw error;
    }
  }
}
