# VirusTotal Chrome Extension

A Chrome extension that integrates with your VirusTotal API backend to scan URLs for security threats.

## Features

- **URL Highlighting Detection**: Automatically detects when you highlight/select URLs on any webpage
- **One-Click Scanning**: Shows a floating scan button when URLs are selected
- **Real-time Results**: Displays scan results with detailed security information
- **Recent Scans History**: View your recent URL scans in the popup
- **Configurable Settings**: Customize API endpoint, notifications, and auto-scan behavior
- **Context Menu Integration**: Right-click on selected URLs to scan them
- **Native Notifications**: Get Chrome notifications for scan results

## Setup

### Prerequisites

1. Your VirusTotal API backend must be running (the NestJS application)
2. Node.js and npm/pnpm installed for building the extension

### Building the Extension

1. Install dependencies:
   ```bash
   cd chrome-extension
   npm install
   ```

2. Build the extension:
   ```bash
   npm run build
   ```

3. The built extension will be in the `dist/` folder

### Installing in Chrome

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" in the top right
3. Click "Load unpacked" and select the `dist/` folder
4. The extension should now be installed and active

### Configuration

1. Click the extension icon in the Chrome toolbar
2. In the popup, configure:
   - **API Endpoint**: Set to your backend URL (default: `http://localhost:3000/api/virustotal`)
   - **Show notifications**: Enable/disable Chrome notifications
   - **Auto-scan selected URLs**: Enable/disable automatic scanning when URLs are highlighted

## Usage

### Method 1: Text Selection
1. Highlight/select any URL on a webpage
2. A blue "Scan URL with VirusTotal" button will appear
3. Click the button to scan the URL
4. Results will be displayed in a notification

### Method 2: Context Menu
1. Highlight/select any URL on a webpage
2. Right-click and select "Scan with VirusTotal"
3. Results will be displayed in a notification

### Method 3: Manual Entry
1. Click the extension icon in the toolbar
2. Enter a URL in the "Quick Scan" field
3. Click "Scan URL" or press Enter
4. View results in the popup and recent scans history

## API Integration

The extension communicates with your NestJS VirusTotal API backend:

- **Endpoint**: `POST /api/virustotal/scan`
- **Request Body**: `{ "url": "https://example.com" }`
- **Response**: Standard VirusTotal API response format

Make sure your backend is running and accessible from the extension.

## Development

### Project Structure

```
chrome-extension/
├── src/
│   ├── background.ts      # Service worker for API calls
│   ├── content.ts         # Content script for URL detection
│   ├── popup.ts          # Popup UI logic
│   ├── popup.html        # Popup UI template
│   └── types.ts          # TypeScript type definitions
├── icons/                # Extension icons
├── manifest.json         # Chrome extension manifest
├── webpack.config.js     # Build configuration
├── tsconfig.json        # TypeScript configuration
└── package.json         # Dependencies and scripts
```

### Development Commands

- `npm run dev` - Build in development mode with watch
- `npm run build` - Build for production
- `npm run clean` - Clean build artifacts

### TypeScript

The entire extension is written in TypeScript for better type safety and development experience. All source files are in the `src/` directory and compiled to JavaScript in the `dist/` directory.

## Security Notes

- The extension only scans URLs when explicitly requested by the user
- No automatic background scanning of browsing activity
- All API calls go through your own backend, not directly to VirusTotal
- Scan results are stored locally in Chrome's storage for the recent scans feature

## Troubleshooting

### Extension not working
1. Check that the extension is enabled in `chrome://extensions/`
2. Verify the API endpoint is correct in the extension settings
3. Ensure your backend is running and accessible

### API errors
1. Check the browser console for error messages
2. Verify your VirusTotal API key is configured in the backend
3. Check network connectivity to your backend

### Build errors
1. Ensure all dependencies are installed: `npm install`
2. Check TypeScript compilation: `npx tsc --noEmit`
3. Verify webpack configuration is correct

## License

MIT License - see your main project license for details.
