# Icon Creation Instructions

This extension needs the following icon files:

- `icon16.png` - 16x16 pixels
- `icon32.png` - 32x32 pixels  
- `icon48.png` - 48x48 pixels
- `icon128.png` - 128x128 pixels

## Recommended Design

- Shield icon with a checkmark or virus scanner symbol
- Blue color scheme matching the extension UI (#2196F3)
- Clean, modern design that works at small sizes

## Creating Icons

You can create these icons using:
1. Any graphics editor (Photoshop, GIMP, Canva, etc.)
2. Online icon generators
3. Icon libraries (Font Awesome, Material Icons, etc.)

## Temporary Solution

For development, you can use any 16x16, 32x32, 48x48, and 128x128 PNG files as placeholders.
The extension will work without custom icons, but Chrome will show a default extension icon.

## File Placement

Place all icon files directly in the `chrome-extension/icons/` directory:

```
chrome-extension/
├── icons/
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   └── icon128.png
└── ...
```
