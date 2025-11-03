<p align="center">
  <a href="https://github.com/covoyage/kairoa">
    <img width="200px" src="https://github.com/covoyage/kairoa/raw/main/src-tauri/icons/icon.png">
  </a>
</p>

<h1 align="center">
  💫 Kairoa ➟ Developer Toolbox 💫
</h1>

<p align="center">
    A modern, cross-platform desktop utility application for developers.
</p>

<div align="left">

**English | [简体中文](./README_zh.md)**

</div>

<p align="center">
  <img src="screenshots/kairoa_en.png" alt="Main Window" style="max-width: 100%; height: auto;" />
</p>

## Features

### 🔐 Hash Calculator
- Calculate hash values for text and files
- Support for multiple algorithms: MD5, SHA-1, SHA-256, SHA-384, SHA-512
- Drag-and-drop file support
- Copy hash values with visual feedback

### ⏰ Time Converter
- Convert between timestamps and dates
- Support for timezone selection (IANA timezone list)
- Searchable timezone dropdown
- Display results in multiple formats (YYYY-MM-DD HH:mm:ss and ISO format)
- Quick access to current time

### 🔑 UUID Generator
- Generate single or multiple UUIDs
- Option to include/exclude hyphens
- Copy individual UUIDs or copy all at once
- Configurable count

### 📝 JSON Formatter
- Format and minify JSON
- Syntax highlighting for formatted JSON
- Real-time validation
- Copy formatted JSON to clipboard

### 🔧 Encode/Decode
- **Base64**: Encode/decode text and images
- **URL**: Encode/decode URL strings
- **Image/Base64**: Convert images to/from Base64 format
- Image preview and download support
- Side-by-side input/output layout

## Interface

- 🌓 **Light/Dark Theme**: Switch between light and dark modes
- 🌍 **Internationalization**: Support for English and Chinese
- 🎨 **Modern UI**: Built with Tailwind CSS
- 📱 **Responsive Design**: Clean and intuitive interface

## Tech Stack

- **Frontend**: SvelteKit 5, TypeScript, Tailwind CSS
- **Desktop**: Tauri 2
- **Icons**: Lucide Svelte
- **Cryptography**: crypto-js

## Prerequisites

- Node.js 18+ and npm
- Rust (latest stable version)
- System dependencies for Tauri:
  - **macOS**: Xcode Command Line Tools
  - **Linux**: System dependencies (see [Tauri documentation](https://tauri.app/v1/guides/getting-started/prerequisites))
  - **Windows**: Microsoft Visual Studio C++ Build Tools

## Installation

This project runs a GitHub CI to build binaries for all platforms. Head to [Releases](https://github.com/covoyage/kairoa/releases) and download the binary as per your requirements.

### macOS

Since the macOS binary is not code-signed with an Apple Developer certificate, you may need to remove the quarantine attribute before running the application:

```bash
xattr -r -c /Applications/kairoa.app
```

This command removes the extended attributes that macOS applies to downloaded applications, allowing you to run the app without Gatekeeper warnings.

## development

1. Clone the repository:
```bash
git clone https://github.com/covoyage/kairoa.git
cd kairoa
```

2. Install dependencies:
```bash
npm install
```

3. Run the development server:
```bash
npm run tauri dev
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style

- Follow TypeScript best practices
- Use Svelte 5 runes (`$state`, `$derived`, `$effect`)
- Follow the existing code style and formatting
- Add comments for complex logic

## License

Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have questions, please open an issue on GitHub.

---

Made with ❤️ using Tauri + SvelteKit

