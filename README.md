# VirusTotal Chrome Extension

A powerful Chrome extension that integrates with VirusTotal API to scan URLs for security threats in real-time.

## 🚀 Features

### Core Functionality
- **Real-time URL Scanning** - Scan any URL for malware, phishing, and security threats
- **Multiple Scan Methods** - Text selection, persistent buttons, drag & drop, and context menu
- **Smart Caching** - 24-hour cache system for instant results on previously scanned URLs
- **Hyperlink Detection** - Automatically detects URLs in links, buttons, images, and JavaScript handlers

### User Interface
- **Persistent Scan Buttons** - Small blue 🛡️ buttons next to every URL on webpages
- **Keyboard Toggle** - Press 'Q' to show/hide scan buttons (when not typing)
- **Drag & Drop Zone** - Drag URLs from anywhere to scan them instantly
- **Right-Click Context Menu** - Scan URLs directly from the context menu
- **Modern Popup** - Clean interface with scan history and settings

### Technical Features
- **100% TypeScript** - Fully typed for better development experience
- **Fast Build System** - Optimized webpack configuration with caching
- **Chrome APIs Integration** - Uses storage, notifications, context menus, and messaging
- **Responsive Design** - Works on all screen sizes and page layouts

## 🛠️ Installation

### Prerequisites
- Node.js 18+ and pnpm
- VirusTotal API backend running (NestJS application)
- Chrome browser with Developer mode enabled

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/FictionFoxy/virus-total-extension.git
   cd virus-total-extension
   ```

2. **Install dependencies**:
   ```bash
   cd chrome-extension
   pnpm install
   ```

3. **Build the extension**:
   ```bash
   # Fast development build (5 seconds)
   pnpm run build:fast
   
   # Production build (optimized)
   pnpm run build
   ```

4. **Install in Chrome**:
   - Open `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `chrome-extension/dist` folder

5. **Configure the extension**:
   - Click the extension icon in Chrome toolbar
   - Set API endpoint to your backend (default: `http://localhost:3000/api/virustotal`)
   - Configure notification and auto-scan preferences

## 🎮 Usage

### Scanning Methods

#### 1. Persistent Blue Buttons
- Small 🛡️ buttons appear next to every URL automatically
- Click any button to scan that specific URL
- Press 'Q' to toggle visibility when not typing in input fields

#### 2. Text Selection
- Highlight any URL text on a webpage
- Blue "Scan URL with VirusTotal" button appears
- Click to scan the selected URL

#### 3. Drag & Drop
- Drag any URL from address bar, links, or text
- Blue overlay appears with drop zone
- Drop anywhere on the page to scan

#### 4. Context Menu
- Right-click on selected URLs or hyperlinks
- Choose "Scan with VirusTotal" from context menu

#### 5. Manual Entry
- Click extension icon to open popup
- Enter URL in "Quick Scan" field
- View results and scan history

### Keyboard Shortcuts
- **Q** - Toggle scan buttons visibility (when not typing)

## 🏗️ Architecture

### Project Structure
```
virus-total-extension/
├── chrome-extension/           # Chrome extension source
│   ├── src/
│   │   ├── background.ts      # Service worker for API calls
│   │   ├── content.ts         # Content script for URL detection
│   │   ├── popup.ts          # Popup UI logic
│   │   ├── popup.html        # Popup interface
│   │   └── types.ts          # TypeScript definitions
│   ├── manifest.json         # Extension configuration
│   ├── webpack.config.js     # Build configuration
│   └── package.json          # Dependencies
├── src/                      # NestJS backend source
│   └── virustotal/          # VirusTotal API integration
├── .cursorrules             # Development guidelines
└── README.md               # This file
```

### API Integration
The extension communicates with a NestJS backend that handles VirusTotal API calls:
- **Endpoint**: `POST /api/virustotal/scan`
- **Request**: `{ "url": "https://example.com" }`
- **Response**: Standard VirusTotal scan results with safety analysis

### Caching System
- **Duration**: 24 hours per URL
- **Storage**: In-memory cache with automatic cleanup
- **Capacity**: Maximum 1000 cached results
- **Performance**: Instant responses for cached URLs

## 🔧 Development

### Build Commands
```bash
# Fast development build (recommended for development)
pnpm run build:fast

# Production build (optimized and minified)
pnpm run build

# Watch mode for continuous development
pnpm run dev

# Clean build artifacts
pnpm run clean
```

### Development Workflow
1. Make changes to TypeScript source files
2. Run `pnpm run build:fast` for quick builds
3. Reload extension in Chrome (`chrome://extensions/`)
4. Test functionality on various websites

### Git Workflow
- Uses conventional commits (`feat:`, `fix:`, `docs:`, etc.)
- Feature branches for new functionality
- Automatic pushing for FictionFoxy repositories
- Atomic commits with descriptive messages

## 🔒 Security & Privacy

### Data Handling
- **No automatic scanning** - URLs only scanned when explicitly requested
- **Local storage only** - Scan history stored locally in Chrome
- **API proxy** - All VirusTotal calls go through your backend, not directly
- **No tracking** - Extension doesn't collect or transmit user data

### Permissions
- `activeTab` - Access current tab for URL detection
- `storage` - Store scan results and settings locally
- `notifications` - Show scan result notifications
- `contextMenus` - Add right-click scan option

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes following the TypeScript and git conventions
4. Commit using conventional format: `git commit -m "feat: add amazing feature"`
5. Push to your branch: `git push origin feature/amazing-feature`
6. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for providing the security scanning API
- [Chrome Extensions API](https://developer.chrome.com/docs/extensions/) for the platform
- [NestJS](https://nestjs.com/) for the backend framework
- [TypeScript](https://www.typescriptlang.org/) for type safety and developer experience