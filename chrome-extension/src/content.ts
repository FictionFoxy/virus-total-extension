import { ChromeMessage, ScanResult, StoredScanResult, NotificationOptions, NotificationType } from './types';

class VirusTotalScanner {
  private selectedText: string = '';
  private isScanning: boolean = false;
  private lastScanResult: ScanResult | null = null;
  private buttonsVisible: boolean = true;
  private dragZone: HTMLElement | null = null;

  constructor() {
    this.init();
  }

  private init(): void {
    console.log('VirusTotalScanner: Initializing content script');
    
    // Listen for text selection
    document.addEventListener('mouseup', this.handleTextSelection.bind(this));
    document.addEventListener('keyup', this.handleTextSelection.bind(this));
    
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener(this.handleMessage.bind(this));
    
    // Add context menu listener
    document.addEventListener('contextmenu', this.handleContextMenu.bind(this));
    
    // Add persistent scan buttons to all URLs on page load
    this.addPersistentScanButtons();
    
    // Watch for dynamic content changes
    this.observePageChanges();
    
    // Add keyboard shortcut listener
    this.setupKeyboardShortcuts();
    
    // Add drag & drop functionality
    this.setupDragAndDrop();
    
    console.log('VirusTotalScanner: Event listeners added');
  }

  private handleTextSelection(event: Event): void {
    const selection = window.getSelection();
    if (!selection) return;
    
    const selectedText = selection.toString().trim();
    console.log('VirusTotalScanner: Text selected:', selectedText);
    
    // Check for URLs in selected text OR in hyperlinks within the selection
    let urlToScan: string | null = null;
    
    if (selectedText) {
      this.selectedText = selectedText;
      
      // First, check if selected text itself is a URL
      if (this.isValidUrl(selectedText)) {
        urlToScan = selectedText;
        console.log('VirusTotalScanner: Selected text is a URL:', selectedText);
      } else {
        // Check if selection contains or is within hyperlinked elements
        const extractedUrl = this.extractUrlFromSelection(selection);
        if (extractedUrl) {
          urlToScan = extractedUrl;
          console.log('VirusTotalScanner: Found URL in hyperlink:', extractedUrl);
        }
      }
      
      if (urlToScan) {
        console.log('VirusTotalScanner: Showing scan option for URL:', urlToScan);
        this.showScanOption(urlToScan);
      } else {
        console.log('VirusTotalScanner: No valid URL found in selection');
        this.hideScanOption();
      }
    } else {
      console.log('VirusTotalScanner: No text selected, hiding scan option');
      this.hideScanOption();
    }
  }

  private handleContextMenu(event: Event): void {
    const selection = window.getSelection();
    if (!selection) return;
    
    const selectedText = selection.toString().trim();
    let urlForContext: string | null = null;
    
    if (selectedText) {
      // Check if selected text is a URL
      if (this.isValidUrl(selectedText)) {
        urlForContext = selectedText;
      } else {
        // Check for hyperlinks in selection
        urlForContext = this.extractUrlFromSelection(selection);
      }
    }
    
    if (urlForContext) {
      // Send message to background script to update context menu
      const message: ChromeMessage = {
        action: 'updateContextMenu',
        url: urlForContext,
        enabled: true
      };
      chrome.runtime.sendMessage(message);
    } else {
      // Hide context menu
      const message: ChromeMessage = {
        action: 'updateContextMenu',
        enabled: false
      };
      chrome.runtime.sendMessage(message);
    }
  }

  private handleMessage(
    request: ChromeMessage, 
    sender: chrome.runtime.MessageSender, 
    sendResponse: (response?: any) => void
  ): boolean {
    console.log('VirusTotalScanner: Received message:', request);
    
    switch (request.action) {
      case 'scanSelectedUrl':
        if (request.url) {
          this.scanUrl(request.url);
        }
        break;
      case 'getScanResult':
        sendResponse({ result: this.lastScanResult });
        break;
    }
    
    return false; // No async response needed
  }

  private extractUrlFromSelection(selection: Selection): string | null {
    try {
      // Get the range of the selection
      if (selection.rangeCount === 0) return null;
      
      const range = selection.getRangeAt(0);
      const container = range.commonAncestorContainer;
      
      // Function to find the closest anchor element
      const findAnchorElement = (node: Node): HTMLAnchorElement | null => {
        let current: Node | null = node;
        
        while (current && current !== document.body) {
          if (current.nodeType === Node.ELEMENT_NODE) {
            const element = current as Element;
            
            // Check if current element is an anchor
            if (element.tagName === 'A') {
              return element as HTMLAnchorElement;
            }
            
            // Check if current element has onclick with URL
            const onclick = element.getAttribute('onclick');
            if (onclick && (onclick.includes('window.open') || onclick.includes('location.href'))) {
              const urlMatch = onclick.match(/['"`](https?:\/\/[^'"`]+)['"`]/);
              if (urlMatch && urlMatch[1]) {
                // Create a temporary anchor element to return
                const tempAnchor = document.createElement('a');
                tempAnchor.href = urlMatch[1];
                return tempAnchor;
              }
            }
          }
          current = current.parentNode;
        }
        return null;
      };
      
      // Look for anchor elements in different ways
      let anchorElement: HTMLAnchorElement | null = null;
      
      // 1. Check if selection contains anchor elements
      const fragment = range.cloneContents();
      const anchorsInSelection = fragment.querySelectorAll('a[href]');
      if (anchorsInSelection.length > 0) {
        // We need to find the original anchor in the document, not the cloned one
        // So we'll skip this approach and rely on the other methods
      }
      
      // 2. Check if selection is within an anchor element
      if (!anchorElement) {
        anchorElement = findAnchorElement(container);
      }
      
      // 3. Check if selection starts or ends within an anchor
      if (!anchorElement) {
        anchorElement = findAnchorElement(range.startContainer) || findAnchorElement(range.endContainer);
      }
      
      // Extract and validate the URL
      if (anchorElement) {
        const href = anchorElement.href || anchorElement.getAttribute('href');
        if (href) {
          console.log('VirusTotalScanner: Found href attribute:', href);
          
          // Filter out javascript:, mailto:, tel:, etc.
          if (href.startsWith('http://') || href.startsWith('https://')) {
            return href;
          }
          
          // Handle relative URLs by converting to absolute
          if (href.startsWith('/') || href.startsWith('./') || href.startsWith('../')) {
            try {
              const absoluteUrl = new URL(href, window.location.href).href;
              console.log('VirusTotalScanner: Converted relative URL to absolute:', absoluteUrl);
              return absoluteUrl;
            } catch (e) {
              console.log('VirusTotalScanner: Failed to convert relative URL:', e);
            }
          }
        }
      }
      
      return null;
    } catch (error) {
      console.error('VirusTotalScanner: Error extracting URL from selection:', error);
      return null;
    }
  }

  private isValidUrl(text: string): boolean {
    // Enhanced URL detection - more permissive patterns
    const urlPatterns = [
      // Standard HTTP/HTTPS URLs
      /^https?:\/\/[^\s]+$/i,
      // URLs without protocol - simplified
      /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}([\/\?#].*)?$/,
      // IP addresses
      /^https?:\/\/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::[0-9]{1,5})?(?:\/.*)?$/i,
      // Localhost
      /^https?:\/\/localhost(?::[0-9]{1,5})?(?:\/.*)?$/i,
      // Common domains without protocol
      /^(www\.)?[a-zA-Z0-9-]+\.(com|org|net|edu|gov|mil|int|co|io|me|ly|tv|cc|tk|ml|ga|cf)([\/\?#].*)?$/i
    ];
    
    const isValid = urlPatterns.some(pattern => pattern.test(text));
    console.log('VirusTotalScanner: URL validation for "' + text + '":', isValid);
    return isValid;
  }

  private normalizeUrl(url: string): string {
    // Add protocol if missing
    if (!/^https?:\/\//i.test(url)) {
      // Check if it looks like a secure site or use http as default
      if (url.includes('secure') || url.includes('login') || url.includes('bank')) {
        return 'https://' + url;
      }
      return 'http://' + url;
    }
    return url;
  }

  private showScanOption(url: string): void {
    // Remove existing scan button
    this.hideScanOption();
    
    // Create floating scan button
    const scanButton = document.createElement('div');
    scanButton.id = 'vt-scan-button';
    scanButton.innerHTML = `
      <div style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: #2196F3;
        color: white;
        padding: 8px 16px;
        border-radius: 20px;
        font-size: 12px;
        font-family: Arial, sans-serif;
        cursor: pointer;
        z-index: 10000;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        transition: all 0.3s ease;
        user-select: none;
      " onmouseover="this.style.background='#1976D2'" onmouseout="this.style.background='#2196F3'">
        🛡️ Scan URL with VirusTotal
      </div>
    `;
    
    scanButton.addEventListener('click', () => {
      this.scanUrl(url);
    });
    
    document.body.appendChild(scanButton);
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
      this.hideScanOption();
    }, 5000);
  }

  private hideScanOption(): void {
    const existingButton = document.getElementById('vt-scan-button');
    if (existingButton) {
      existingButton.remove();
    }
  }

  private async scanUrl(url: string): Promise<void> {
    if (this.isScanning) {
      console.log('VirusTotalScanner: Already scanning, ignoring request');
      return;
    }
    
    this.isScanning = true;
    const normalizedUrl = this.normalizeUrl(url);
    console.log('VirusTotalScanner: Starting scan for URL:', normalizedUrl);
    
    // Show scanning notification
    this.showNotification({
      message: 'Scanning URL...',
      type: 'info',
      url: normalizedUrl
    });
    
    try {
      // Send scan request to background script
      const message: ChromeMessage = {
        action: 'scanUrl',
        url: normalizedUrl
      };
      
      console.log('VirusTotalScanner: Sending message to background:', message);
      
      // Use promise-based approach for better error handling
      chrome.runtime.sendMessage(message, (response) => {
        console.log('VirusTotalScanner: Received response:', response);
        
        // Check for Chrome runtime errors
        if (chrome.runtime.lastError) {
          console.error('VirusTotalScanner: Chrome runtime error:', chrome.runtime.lastError);
          this.showNotification({
            message: 'Extension error: ' + chrome.runtime.lastError.message,
            type: 'error',
            url: normalizedUrl
          });
          return;
        }
        
        if (response && response.success) {
          console.log('VirusTotalScanner: Scan successful, handling result');
          this.handleScanResult(response.data, normalizedUrl);
        } else {
          console.error('VirusTotalScanner: Scan failed:', response);
          this.showNotification({
            message: 'Scan failed: ' + (response?.error || 'Unknown error'),
            type: 'error',
            url: normalizedUrl
          });
        }
      });
    } catch (error) {
      console.error('VirusTotalScanner: Scan error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.showNotification({
        message: 'Scan failed: ' + errorMessage,
        type: 'error',
        url: normalizedUrl
      });
    } finally {
      this.isScanning = false;
      this.hideScanOption();
    }
  }

  private handleScanResult(result: ScanResult, url: string): void {
    console.log('VirusTotalScanner: Handling scan result:', result);
    this.lastScanResult = { ...result };
    
    const isSafe = result.safe;
    const message = isSafe ? 'URL is safe' : 'URL may be unsafe!';
    const type: NotificationType = isSafe ? 'success' : 'warning';
    
    // Show result notification
    this.showNotification({
      message,
      type,
      url,
      details: result
    });
    
    // Store result for popup
    const storedResult: StoredScanResult = {
      url,
      result,
      timestamp: new Date().toISOString()
    };
    
    const storageKey = `scan_${Date.now()}`;
    console.log('VirusTotalScanner: Storing result with key:', storageKey, storedResult);
    
    chrome.storage.local.set({
      [storageKey]: storedResult
    }).then(() => {
      console.log('VirusTotalScanner: Result stored successfully');
    }).catch((error) => {
      console.error('VirusTotalScanner: Failed to store result:', error);
    });
  }

  private showNotification(options: NotificationOptions): void {
    const { message, type, url, details, duration = type === 'error' ? 8000 : 5000 } = options;
    
    // Create notification element
    const notification = document.createElement('div');
    notification.id = 'vt-notification';
    
    const bgColor = {
      'info': '#2196F3',
      'success': '#4CAF50',
      'warning': '#FF9800',
      'error': '#F44336'
    }[type];
    
    const icon = {
      'info': '🔍',
      'success': '✅',
      'warning': '⚠️',
      'error': '❌'
    }[type];
    
    const displayUrl = url.length > 50 ? url.substring(0, 50) + '...' : url;
    
    notification.innerHTML = `
      <div style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${bgColor};
        color: white;
        padding: 12px 16px;
        border-radius: 8px;
        font-size: 14px;
        font-family: Arial, sans-serif;
        z-index: 10001;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        max-width: 300px;
        word-wrap: break-word;
      ">
        <div style="display: flex; align-items: center; margin-bottom: 4px;">
          <span style="margin-right: 8px; font-size: 16px;">${icon}</span>
          <strong>VirusTotal Scanner</strong>
        </div>
        <div style="margin-bottom: 8px;">${message}</div>
        <div style="font-size: 12px; opacity: 0.9; word-break: break-all;">
          ${displayUrl}
        </div>
        ${details ? `
          <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.3); font-size: 11px;">
            <div>Malicious: ${details.last_analysis_stats.malicious}</div>
            <div>Suspicious: ${details.last_analysis_stats.suspicious}</div>
            <div>Harmless: ${details.last_analysis_stats.harmless}</div>
          </div>
        ` : ''}
        <button onclick="this.parentElement.parentElement.remove()" style="
          position: absolute;
          top: 4px;
          right: 4px;
          background: none;
          border: none;
          color: white;
          cursor: pointer;
          font-size: 16px;
          width: 20px;
          height: 20px;
          display: flex;
          align-items: center;
          justify-content: center;
        ">×</button>
      </div>
    `;
    
    // Remove existing notification
    const existing = document.getElementById('vt-notification');
    if (existing) existing.remove();
    
    document.body.appendChild(notification);
    
    // Auto-remove after delay
    setTimeout(() => {
      if (notification.parentElement) {
        notification.remove();
      }
    }, duration);
  }

  private addPersistentScanButtons(): void {
    console.log('VirusTotalScanner: Adding persistent scan buttons');
    
    // Find all anchor elements with href
    const anchors = document.querySelectorAll('a[href]');
    
    anchors.forEach((anchor, index) => {
      const anchorElement = anchor as HTMLAnchorElement;
      const href = anchorElement.href;
      
      // Skip if not a valid URL or already has a scan button
      if (!href || !href.startsWith('http') || anchorElement.dataset.vtScanned) {
        return;
      }
      
      // Mark as processed
      anchorElement.dataset.vtScanned = 'true';
      
      // Create scan button
      const scanBtn = this.createPersistentScanButton(href, `vt-btn-${index}`);
      
      // Position button next to the link
      this.positionScanButton(anchorElement, scanBtn);
    });
  }

  private createPersistentScanButton(url: string, id: string): HTMLElement {
    const button = document.createElement('div');
    button.id = id;
    button.className = 'vt-persistent-scan-btn';
    button.title = `Scan ${url} with VirusTotal`;
    button.innerHTML = '🛡️';
    
    // Styling
    button.style.cssText = `
      position: absolute;
      width: 16px;
      height: 16px;
      background: #2196F3;
      color: white;
      border-radius: 3px;
      font-size: 10px;
      line-height: 16px;
      text-align: center;
      cursor: pointer;
      z-index: 9999;
      box-shadow: 0 1px 3px rgba(0,0,0,0.3);
      transition: all 0.2s ease;
      user-select: none;
      font-family: Arial, sans-serif;
    `;
    
    // Hover effects
    button.addEventListener('mouseenter', () => {
      button.style.background = '#1976D2';
      button.style.transform = 'scale(1.1)';
    });
    
    button.addEventListener('mouseleave', () => {
      button.style.background = '#2196F3';
      button.style.transform = 'scale(1)';
    });
    
    // Click handler
    button.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      console.log('VirusTotalScanner: Persistent button clicked for URL:', url);
      this.scanUrl(url);
    });
    
    return button;
  }

  private positionScanButton(anchor: HTMLAnchorElement, button: HTMLElement): void {
    // Add button to document
    document.body.appendChild(button);
    
    // Position it next to the anchor
    const updatePosition = () => {
      const rect = anchor.getBoundingClientRect();
      const scrollX = window.pageXOffset || document.documentElement.scrollLeft;
      const scrollY = window.pageYOffset || document.documentElement.scrollTop;
      
      button.style.left = `${rect.right + scrollX + 2}px`;
      button.style.top = `${rect.top + scrollY + (rect.height - 16) / 2}px`;
    };
    
    updatePosition();
    
    // Update position on scroll and resize
    const updateHandler = () => updatePosition();
    window.addEventListener('scroll', updateHandler);
    window.addEventListener('resize', updateHandler);
    
    // Store cleanup function
    (button as any)._cleanup = () => {
      window.removeEventListener('scroll', updateHandler);
      window.removeEventListener('resize', updateHandler);
    };
  }

  private observePageChanges(): void {
    // Watch for dynamically added content
    const observer = new MutationObserver((mutations) => {
      let shouldUpdate = false;
      
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              const element = node as Element;
              if (element.tagName === 'A' || element.querySelector('a[href]')) {
                shouldUpdate = true;
              }
            }
          });
        }
      });
      
      if (shouldUpdate) {
        // Debounce updates
        setTimeout(() => {
          this.addPersistentScanButtons();
        }, 500);
      }
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  private setupKeyboardShortcuts(): void {
    document.addEventListener('keydown', (event) => {
      // Only trigger when not typing in input fields
      const activeElement = document.activeElement;
      const isTyping = activeElement && (
        activeElement.tagName === 'INPUT' ||
        activeElement.tagName === 'TEXTAREA' ||
        activeElement.contentEditable === 'true'
      );

      if (!isTyping && event.key.toLowerCase() === 'q' && !event.ctrlKey && !event.altKey && !event.metaKey) {
        event.preventDefault();
        this.toggleScanButtons();
      }
    });
  }

  private toggleScanButtons(): void {
    this.buttonsVisible = !this.buttonsVisible;
    const buttons = document.querySelectorAll('.vt-persistent-scan-btn');
    
    buttons.forEach((button) => {
      const btnElement = button as HTMLElement;
      btnElement.style.display = this.buttonsVisible ? 'block' : 'none';
    });

    // Show notification about toggle
    this.showNotification({
      message: `Scan buttons ${this.buttonsVisible ? 'shown' : 'hidden'}. Press 'Q' to toggle.`,
      type: 'info',
      url: 'Toggle',
      duration: 2000
    });

    console.log('VirusTotalScanner: Scan buttons', this.buttonsVisible ? 'shown' : 'hidden');
  }

  private setupDragAndDrop(): void {
    // Create drag zone
    this.createDragZone();

    // Listen for drag events on the entire page
    document.addEventListener('dragover', this.handleDragOver.bind(this));
    document.addEventListener('drop', this.handleDrop.bind(this));
    document.addEventListener('dragenter', this.handleDragEnter.bind(this));
    document.addEventListener('dragleave', this.handleDragLeave.bind(this));
  }

  private createDragZone(): void {
    this.dragZone = document.createElement('div');
    this.dragZone.id = 'vt-drag-zone';
    this.dragZone.innerHTML = `
      <div style="
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 100%;
        color: white;
        font-family: Arial, sans-serif;
      ">
        <div style="font-size: 48px; margin-bottom: 16px;">🛡️</div>
        <div style="font-size: 18px; font-weight: bold; margin-bottom: 8px;">Drop URLs here to scan</div>
        <div style="font-size: 14px; opacity: 0.9;">Drag and drop URLs from anywhere</div>
      </div>
    `;

    this.dragZone.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(33, 150, 243, 0.9);
      z-index: 999999;
      display: none;
      backdrop-filter: blur(4px);
    `;

    document.body.appendChild(this.dragZone);
  }

  private handleDragOver(event: DragEvent): void {
    event.preventDefault();
    if (this.dragZone) {
      this.dragZone.style.display = 'flex';
    }
  }

  private handleDragEnter(event: DragEvent): void {
    event.preventDefault();
    if (this.dragZone) {
      this.dragZone.style.display = 'flex';
    }
  }

  private handleDragLeave(event: DragEvent): void {
    // Only hide if leaving the window
    if (!event.relatedTarget) {
      if (this.dragZone) {
        this.dragZone.style.display = 'none';
      }
    }
  }

  private handleDrop(event: DragEvent): void {
    event.preventDefault();
    
    if (this.dragZone) {
      this.dragZone.style.display = 'none';
    }

    const items = event.dataTransfer?.items;
    if (!items) return;

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      
      if (item.kind === 'string') {
        item.getAsString((data) => {
          console.log('VirusTotalScanner: Dropped data:', data);
          
          // Check if dropped data is a URL
          if (this.isValidUrl(data)) {
            console.log('VirusTotalScanner: Valid URL dropped, scanning:', data);
            this.scanUrl(data);
          } else {
            // Try to extract URLs from the dropped text
            const urlMatch = data.match(/https?:\/\/[^\s]+/g);
            if (urlMatch && urlMatch.length > 0) {
              console.log('VirusTotalScanner: Found URL in dropped text, scanning:', urlMatch[0]);
              this.scanUrl(urlMatch[0]);
            } else {
              this.showNotification({
                message: 'No valid URL found in dropped content',
                type: 'error',
                url: 'Drop'
              });
            }
          }
        });
      }
    }
  }
}

// Initialize scanner when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new VirusTotalScanner();
  });
} else {
  new VirusTotalScanner();
}
