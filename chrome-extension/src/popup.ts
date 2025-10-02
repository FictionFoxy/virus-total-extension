import { ChromeMessage, ExtensionConfig, StoredScanResult, ScanResult } from './types';

class PopupManager {
  private urlInput!: HTMLInputElement;
  private scanButton!: HTMLButtonElement;
  private recentScansContainer!: HTMLElement;
  private notificationsToggle!: HTMLElement;
  private autoScanToggle!: HTMLElement;
  private apiEndpointInput!: HTMLInputElement;
  private config!: ExtensionConfig;

  constructor() {
    this.initializeElements();
    this.init();
  }

  private initializeElements(): void {
    this.urlInput = document.getElementById('urlInput') as HTMLInputElement;
    this.scanButton = document.getElementById('scanButton') as HTMLButtonElement;
    this.recentScansContainer = document.getElementById('recentScans') as HTMLElement;
    this.notificationsToggle = document.getElementById('notificationsToggle') as HTMLElement;
    this.autoScanToggle = document.getElementById('autoScanToggle') as HTMLElement;
    this.apiEndpointInput = document.getElementById('apiEndpoint') as HTMLInputElement;

    if (!this.urlInput || !this.scanButton || !this.recentScansContainer || 
        !this.notificationsToggle || !this.autoScanToggle || !this.apiEndpointInput) {
      throw new Error('Required DOM elements not found');
    }
  }

  private async init(): Promise<void> {
    // Load configuration
    await this.loadConfig();
    
    // Set up event listeners
    this.setupEventListeners();
    
    // Load recent scans
    await this.loadRecentScans();
  }

  private async loadConfig(): Promise<void> {
    try {
      const message: ChromeMessage = { action: 'getConfig' };
      this.config = await chrome.runtime.sendMessage(message);
      
      // Update UI with config values
      this.updateConfigUI();
    } catch (error) {
      console.error('Failed to load config:', error);
      // Use default config
      this.config = {
        apiEndpoint: 'http://localhost:3000/api/virustotal',
        autoScan: true,
        showNotifications: true
      };
      this.updateConfigUI();
    }
  }

  private updateConfigUI(): void {
    // Update toggles
    this.notificationsToggle.classList.toggle('active', this.config.showNotifications);
    this.autoScanToggle.classList.toggle('active', this.config.autoScan);
    
    // Update API endpoint
    this.apiEndpointInput.value = this.config.apiEndpoint;
  }

  private setupEventListeners(): void {
    // Scan button
    this.scanButton.addEventListener('click', this.handleScanClick.bind(this));
    
    // URL input - scan on Enter
    this.urlInput.addEventListener('keypress', (event) => {
      if (event.key === 'Enter') {
        this.handleScanClick();
      }
    });
    
    // Settings toggles
    this.notificationsToggle.addEventListener('click', () => {
      this.toggleSetting('showNotifications');
    });
    
    this.autoScanToggle.addEventListener('click', () => {
      this.toggleSetting('autoScan');
    });
    
    // API endpoint input
    this.apiEndpointInput.addEventListener('blur', this.handleApiEndpointChange.bind(this));
    this.apiEndpointInput.addEventListener('keypress', (event) => {
      if (event.key === 'Enter') {
        this.handleApiEndpointChange();
      }
    });
  }

  private async handleScanClick(): Promise<void> {
    const url = this.urlInput.value.trim();
    if (!url) {
      this.showError('Please enter a URL to scan');
      return;
    }

    if (!this.isValidUrl(url)) {
      this.showError('Please enter a valid URL');
      return;
    }

    await this.scanUrl(url);
  }

  private async scanUrl(url: string): Promise<void> {
    // Disable scan button and show loading state
    this.scanButton.disabled = true;
    this.scanButton.textContent = 'Scanning...';

    try {
      const message: ChromeMessage = { action: 'scanUrl', url };
      const response = await chrome.runtime.sendMessage(message);

      if (response.success) {
        // Clear input
        this.urlInput.value = '';
        
        // Reload recent scans to show the new result
        await this.loadRecentScans();
        
        this.showSuccess('URL scanned successfully');
      } else {
        this.showError(response.error || 'Scan failed');
      }
    } catch (error) {
      console.error('Scan error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.showError(`Scan failed: ${errorMessage}`);
    } finally {
      // Re-enable scan button
      this.scanButton.disabled = false;
      this.scanButton.textContent = 'Scan URL';
    }
  }

  private async loadRecentScans(): Promise<void> {
    console.log('PopupManager: Loading recent scans');
    try {
      const result = await chrome.storage.local.get(null);
      console.log('PopupManager: Storage result:', result);
      const scanResults: StoredScanResult[] = [];

      // Filter and collect scan results
      for (const [key, value] of Object.entries(result)) {
        if (key.startsWith('scan_') && this.isStoredScanResult(value)) {
          console.log('PopupManager: Found scan result:', key, value);
          scanResults.push(value as StoredScanResult);
        }
      }

      console.log('PopupManager: Total scan results found:', scanResults.length);

      // Sort by timestamp (newest first)
      scanResults.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      // Take only the most recent 10 scans
      const recentScans = scanResults.slice(0, 10);
      console.log('PopupManager: Recent scans to display:', recentScans);

      this.displayRecentScans(recentScans);
    } catch (error) {
      console.error('PopupManager: Failed to load recent scans:', error);
      this.recentScansContainer.innerHTML = '<div class="empty-state">Failed to load recent scans</div>';
    }
  }

  private isStoredScanResult(value: any): value is StoredScanResult {
    return value && 
           typeof value === 'object' && 
           typeof value.url === 'string' && 
           typeof value.timestamp === 'string' && 
           value.result && 
           typeof value.result === 'object';
  }

  private displayRecentScans(scans: StoredScanResult[]): void {
    if (scans.length === 0) {
      this.recentScansContainer.innerHTML = '<div class="empty-state">No recent scans</div>';
      return;
    }

    const html = scans.map(scan => this.createScanResultHTML(scan)).join('');
    this.recentScansContainer.innerHTML = html;
  }

  private createScanResultHTML(scan: StoredScanResult): string {
    const { result, timestamp } = scan;
    const isSafe = result.safe;
    const statusClass = isSafe ? 'safe' : 'unsafe';
    const statusIndicator = isSafe ? 'status-safe' : 'status-unsafe';
    
    const timeAgo = this.getTimeAgo(new Date(timestamp));
    const displayUrl = result.url.length > 40 ? result.url.substring(0, 40) + '...' : result.url;

    return `
      <div class="scan-result ${statusClass}">
        <div class="scan-result-url">
          <span class="status-indicator ${statusIndicator}"></span>
          ${this.escapeHtml(displayUrl)}
        </div>
        <div class="scan-result-stats">
          Malicious: ${result.last_analysis_stats.malicious} | 
          Suspicious: ${result.last_analysis_stats.suspicious} | 
          Harmless: ${result.last_analysis_stats.harmless}
        </div>
        <div class="scan-result-time">${timeAgo}</div>
      </div>
    `;
  }

  private async toggleSetting(setting: 'showNotifications' | 'autoScan'): Promise<void> {
    try {
      const newValue = !this.config[setting];
      this.config[setting] = newValue;

      // Update UI immediately
      if (setting === 'showNotifications') {
        this.notificationsToggle.classList.toggle('active', newValue);
      } else if (setting === 'autoScan') {
        this.autoScanToggle.classList.toggle('active', newValue);
      }

      // Save to background script
      const message: ChromeMessage = { 
        action: 'updateConfig', 
        data: { [setting]: newValue } 
      };
      await chrome.runtime.sendMessage(message);
    } catch (error) {
      console.error('Failed to update setting:', error);
      this.showError('Failed to update setting');
    }
  }

  private async handleApiEndpointChange(): Promise<void> {
    const newEndpoint = this.apiEndpointInput.value.trim();
    
    if (!newEndpoint) {
      this.showError('API endpoint cannot be empty');
      this.apiEndpointInput.value = this.config.apiEndpoint;
      return;
    }

    if (!this.isValidUrl(newEndpoint)) {
      this.showError('Please enter a valid API endpoint URL');
      this.apiEndpointInput.value = this.config.apiEndpoint;
      return;
    }

    try {
      this.config.apiEndpoint = newEndpoint;
      
      const message: ChromeMessage = { 
        action: 'updateConfig', 
        data: { apiEndpoint: newEndpoint } 
      };
      await chrome.runtime.sendMessage(message);
      
      this.showSuccess('API endpoint updated');
    } catch (error) {
      console.error('Failed to update API endpoint:', error);
      this.showError('Failed to update API endpoint');
      this.apiEndpointInput.value = this.config.apiEndpoint;
    }
  }

  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      // Try with protocol prefix
      try {
        new URL('http://' + url);
        return true;
      } catch {
        return false;
      }
    }
  }

  private showError(message: string): void {
    this.showNotification(message, 'error');
  }

  private showSuccess(message: string): void {
    this.showNotification(message, 'success');
  }

  private showNotification(message: string, type: 'success' | 'error'): void {
    // Create temporary notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      left: 50%;
      transform: translateX(-50%);
      background: ${type === 'success' ? '#4CAF50' : '#F44336'};
      color: white;
      padding: 8px 16px;
      border-radius: 4px;
      font-size: 12px;
      z-index: 1000;
      animation: slideDown 0.3s ease;
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
      if (notification.parentElement) {
        notification.remove();
      }
    }, 3000);
  }

  private getTimeAgo(date: Date): string {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    
    return date.toLocaleDateString();
  }

  private escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize popup when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new PopupManager();
  });
} else {
  new PopupManager();
}
