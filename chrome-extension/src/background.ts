import { ChromeMessage, ApiResponse, ScanResult, ScanRequest, ExtensionConfig } from './types';

class BackgroundService {
  private defaultConfig: ExtensionConfig = {
    apiEndpoint: 'http://localhost:3000/api/virustotal',
    autoScan: true,
    showNotifications: true
  };
  
  private cache = new Map<string, { result: ScanResult; timestamp: number }>();
  private readonly CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

  constructor() {
    this.init();
  }

  private init(): void {
    // Initialize extension configuration
    this.initializeConfig();
    
    // Set up message listeners
    chrome.runtime.onMessage.addListener(this.handleMessage.bind(this));
    
    // Set up context menu
    this.setupContextMenu();
    
    // Handle extension installation
    chrome.runtime.onInstalled.addListener(this.handleInstalled.bind(this));
  }

  private async initializeConfig(): Promise<void> {
    try {
      const result = await chrome.storage.sync.get('config');
      if (!result.config) {
        await chrome.storage.sync.set({ config: this.defaultConfig });
      }
    } catch (error) {
      console.error('Failed to initialize config:', error);
    }
  }

  private handleMessage(
    request: ChromeMessage,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response?: any) => void
  ): boolean {
    console.log('BackgroundService: Received message:', request);
    
    switch (request.action) {
      case 'scanUrl':
        if (request.url) {
          console.log('BackgroundService: Processing scan request for URL:', request.url);
          this.scanUrl(request.url).then((response) => {
            console.log('BackgroundService: Scan completed, sending response:', response);
            sendResponse(response);
          }).catch((error) => {
            console.error('BackgroundService: Scan failed:', error);
            sendResponse({
              success: false,
              error: error.message || 'Unknown error'
            });
          });
          return true; // Indicates async response
        }
        break;
      
      case 'updateContextMenu':
        this.updateContextMenu(request.enabled || false, request.url);
        break;
      
      case 'getConfig':
        this.getConfig().then(sendResponse);
        return true;
      
      case 'updateConfig':
        if (request.data) {
          this.updateConfig(request.data).then(sendResponse);
          return true;
        }
        break;
    }
    
    return false;
  }

  private setupContextMenu(): void {
    chrome.contextMenus.create({
      id: 'scan-url',
      title: 'Scan with VirusTotal',
      contexts: ['selection'],
      visible: false
    });

    chrome.contextMenus.onClicked.addListener((info, tab) => {
      if (info.menuItemId === 'scan-url' && info.selectionText && tab?.id) {
        // Send message to content script to scan the selected URL
        chrome.tabs.sendMessage(tab.id, {
          action: 'scanSelectedUrl',
          url: info.selectionText
        });
      }
    });
  }

  private updateContextMenu(enabled: boolean, url?: string): void {
    chrome.contextMenus.update('scan-url', {
      visible: enabled,
      title: url ? `Scan "${url.substring(0, 30)}..." with VirusTotal` : 'Scan with VirusTotal'
    });
  }

  private handleInstalled(details: chrome.runtime.InstalledDetails): void {
    if (details.reason === 'install') {
      // Show welcome notification
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==',
        title: 'VirusTotal Scanner Installed',
        message: 'Select any URL on a webpage to scan it for security threats!'
      });
    }
  }

  private async getConfig(): Promise<ExtensionConfig> {
    try {
      const result = await chrome.storage.sync.get('config');
      return result.config || this.defaultConfig;
    } catch (error) {
      console.error('Failed to get config:', error);
      return this.defaultConfig;
    }
  }

  private async updateConfig(newConfig: Partial<ExtensionConfig>): Promise<ExtensionConfig> {
    try {
      const currentConfig = await this.getConfig();
      const updatedConfig = { ...currentConfig, ...newConfig };
      await chrome.storage.sync.set({ config: updatedConfig });
      return updatedConfig;
    } catch (error) {
      console.error('Failed to update config:', error);
      throw error;
    }
  }

  private async scanUrl(url: string): Promise<ApiResponse<ScanResult>> {
    try {
      // Check cache first
      const cached = this.getCachedResult(url);
      if (cached) {
        console.log('BackgroundService: Using cached result for:', url);
        return {
          success: true,
          data: cached,
          message: `URL scan completed (cached): ${cached.safe ? 'SAFE' : 'UNSAFE'}`
        };
      }

      console.log('BackgroundService: No cache, fetching from API for:', url);
      const config = await this.getConfig();
      const endpoint = `${config.apiEndpoint}/scan`;
      
      const requestBody: ScanRequest = { url };
      
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        const errorText = await response.text();
        let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        
        try {
          const errorJson = JSON.parse(errorText);
          errorMessage = errorJson.message || errorJson.error || errorMessage;
        } catch {
          // Use default error message if JSON parsing fails
        }
        
        throw new Error(errorMessage);
      }

      const result: ApiResponse<ScanResult> = await response.json();
      
      // Cache the result
      if (result.success && result.data) {
        this.setCachedResult(url, result.data);
      }
      
      // Show notification if enabled
      if (config.showNotifications && result.success && result.data) {
        this.showScanNotification(result.data);
      }
      
      return result;
    } catch (error) {
      console.error('Scan error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      
      return {
        success: false,
        error: errorMessage,
        message: `Failed to scan URL: ${errorMessage}`
      };
    }
  }

  private getCachedResult(url: string): ScanResult | null {
    const cached = this.cache.get(url);
    if (cached && Date.now() - cached.timestamp < this.CACHE_DURATION) {
      return cached.result;
    }
    
    // Remove expired cache
    if (cached) {
      this.cache.delete(url);
    }
    
    return null;
  }

  private setCachedResult(url: string, result: ScanResult): void {
    this.cache.set(url, {
      result,
      timestamp: Date.now()
    });
    
    // Clean up old cache entries (keep max 1000 entries)
    if (this.cache.size > 1000) {
      const entries = Array.from(this.cache.entries());
      entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
      
      // Remove oldest 100 entries
      for (let i = 0; i < 100; i++) {
        this.cache.delete(entries[i][0]);
      }
    }
  }

  private showScanNotification(result: ScanResult): void {
    const isSafe = result.safe;
    
    const title = isSafe ? '✅ URL is Safe' : '⚠️ URL May Be Unsafe';
    const message = `${result.url}\n` +
      `Malicious: ${result.last_analysis_stats.malicious}, ` +
      `Suspicious: ${result.last_analysis_stats.suspicious}, ` +
      `Harmless: ${result.last_analysis_stats.harmless}`;

    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==',
      title,
      message: message.length > 320 ? message.substring(0, 317) + '...' : message,
      priority: isSafe ? 1 : 2
    });
  }
}

// Initialize background service
new BackgroundService();
