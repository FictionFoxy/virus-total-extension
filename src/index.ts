// VirusTotal URL scan + notify
// Works in Node.js 18+ and modern browsers
// 1) Set your API key in .env: VIRUS_TOTAL_API_KEY=your_key_here
// 2) Call scanAndNotify('https://example.com')

import * as dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

const VIRUS_TOTAL_API_KEY = process.env.VIRUS_TOTAL_API_KEY;
const VT_BASE = 'https://www.virustotal.com/api/v3';
const isBrowser = typeof window !== 'undefined' && typeof window.document !== 'undefined';

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

interface ScanSummary {
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

interface NotificationMessage {
  title: string;
  body: string;
}

interface WaitOptions {
  intervalMs?: number;
  timeoutMs?: number;
}

// Simple sleep util
const sleep = (ms: number): Promise<void> => new Promise((res) => setTimeout(res, ms));

// Base64url encode (no padding)
function b64url(input: string): string {
  try {
    // Node.js path
    return Buffer.from(input, 'utf8')
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  } catch (_) {
    // Browser path
    const bytes = new TextEncoder().encode(input);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
}

function toIso(tsSec?: number): string | null {
  if (!tsSec) return null;
  return new Date(tsSec * 1000).toISOString();
}

function humanizeDuration(ms: number | null): string {
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
async function fetchJson<T>(url: string, opts: RequestInit = {}): Promise<T | null> {
  const res = await fetch(url, opts);
  if (res.ok) return res.json() as Promise<T>;
  if (res.status === 404) return null;
  const text = await res.text();
  throw new Error(`HTTP ${res.status}: ${text || res.statusText}`);
}

// Get current URL report (if any)
async function getUrlReport(urlStr: string): Promise<UrlReport | null> {
  const id = b64url(urlStr);
  const json = await fetchJson<UrlReport>(`${VT_BASE}/urls/${id}`, {
    method: 'GET',
    headers: {
      accept: 'application/json',
      'x-apikey': VIRUS_TOTAL_API_KEY!,
    },
  });
  return json; // can be null if never seen before
}

// Submit URL for analysis
async function submitUrl(urlStr: string): Promise<string> {
  const body = new URLSearchParams({ url: urlStr });
  const json = await fetchJson<SubmitUrlResponse>(`${VT_BASE}/urls`, {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/x-www-form-urlencoded',
      'x-apikey': VIRUS_TOTAL_API_KEY!,
    },
    body,
  });
  if (!json?.data?.id) throw new Error('No analysis ID returned from VirusTotal.');
  return json.data.id; // analyses/{id}
}

// Wait until analysis completes
async function waitForAnalysis(
  analysisId: string, 
  { intervalMs = 3000, timeoutMs = 180000 }: WaitOptions = {}
): Promise<AnalysisResponse> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const json = await fetchJson<AnalysisResponse>(`${VT_BASE}/analyses/${analysisId}`, {
      method: 'GET',
      headers: { accept: 'application/json', 'x-apikey': VIRUS_TOTAL_API_KEY! },
    });
    const status = json?.data?.attributes?.status;
    if (status === 'completed') return json!;
    if (status && status !== 'queued' && status !== 'running') {
      throw new Error(`Unexpected analysis status: ${status}`);
    }
    await sleep(intervalMs);
  }
  throw new Error('Timed out waiting for analysis to complete.');
}

// Compute safe/unsafe + summary
function summarize(urlStr: string, initialReport: UrlReport | null, finalReport: UrlReport): ScanSummary {
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

  // "Unsafe" if any malicious or suspicious or any negative community votes
  const unsafe =
    (lastAnalysisStats.malicious || 0) + (lastAnalysisStats.suspicious || 0) > 0 ||
    (totalVotes.malicious || 0) > 0;

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
    stale_age_human: wasStale ? humanizeDuration(staleAgeMs) : 'fresh',
    last_submitted_ago: lastSubmittedAgoMs != null ? humanizeDuration(lastSubmittedAgoMs) : 'unknown',
    last_analysis_date: toIso(finalAttr.last_analysis_date),
    last_submission_date: toIso(finalAttr.last_submission_date),
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

function formatNotification(summary: ScanSummary): NotificationMessage {
  const status = summary.safe ? 'SAFE ✅' : 'UNSAFE ❌';
  const stalePart = summary.wasStale
    ? `Stale before rescan: YES (last checked ~${summary.stale_age_human} ago; last submitted ~${summary.last_submitted_ago})`
    : `Stale before rescan: NO`;

  const stats = summary.last_analysis_stats;
  const votes = summary.total_votes;

  return {
    title: `VirusTotal: ${status}`,
    body:
      `URL: ${summary.url}\n` +
      `${stalePart}\n` +
      `Stats — harmless:${stats.harmless}  undetected:${stats.undetected}  suspicious:${stats.suspicious}  malicious:${stats.malicious}  timeout:${stats.timeout}\n` +
      `Community votes — harmless:${votes.harmless}  malicious:${votes.malicious}\n` +
      (summary.last_analysis_date ? `Last analysis: ${summary.last_analysis_date}\n` : '') +
      (summary.last_submission_date ? `Last submission: ${summary.last_submission_date}` : ''),
  };
}

async function notifyUser({ title, body }: NotificationMessage): Promise<void> {
  if (isBrowser && 'Notification' in window) {
    // Browser notification
    const perm = await Notification.requestPermission();
    if (perm === 'granted') {
      new Notification(title, { body });
      return;
    }
    // Fallback to alert
    alert(`${title}\n\n${body}`);
  } else {
    // Node.js: simple console + terminal bell
    console.log(`\n=== ${title} ===\n${body}\n`);
    try {
      process.stdout.write('\x07'); // bell
    } catch (_) {}
  }
}

// Main function
export async function scanAndNotify(urlStr: string): Promise<ScanSummary> {
  if (!VIRUS_TOTAL_API_KEY) {
    throw new Error('Please set VIRUS_TOTAL_API_KEY in your .env file.');
  }

  // 1) Fetch current report (to determine staleness before re-scan)
  const initialReport = await getUrlReport(urlStr);

  // 2) Submit the URL for analysis
  const analysisId = await submitUrl(urlStr);

  // 3) Wait until the analysis completes
  await waitForAnalysis(analysisId);

  // 4) Fetch the final URL report
  const finalReport = await getUrlReport(urlStr);
  if (!finalReport) throw new Error('Final report not found after analysis.');

  // 5) Build summary and notify
  const summary = summarize(urlStr, initialReport, finalReport);
  const message = formatNotification(summary);
  await notifyUser(message);

  return summary; // also return the data for programmatic use
}

// Export utility functions for advanced usage
export {
  getUrlReport,
  submitUrl,
  waitForAnalysis,
  summarize,
  formatNotification,
  notifyUser,
  b64url,
  toIso,
  humanizeDuration
};

// Export types for consumers
export type {
  AnalysisStats,
  TotalVotes,
  UrlReportAttributes,
  UrlReportData,
  UrlReport,
  AnalysisData,
  AnalysisResponse,
  SubmitUrlResponse,
  ScanSummary,
  NotificationMessage,
  WaitOptions
};

// Example usage (commented out for module usage):
// scanAndNotify('https://example.com')
//   .then(summary => console.log('Summary object:', summary))
//   .catch(err => console.error('Error:', err));
