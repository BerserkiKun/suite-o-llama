# Suite-o-llama: AI-Powered Burp Suite Extension for Penetration Testing

## 📋 Table of Contents
- [Overview](#overview)
- [Deep Burp Suite Integration](#deep-burp-suite-integration)
  - [Multi-Tab Integration](#multi-tab-integration)
  - [Core Template Variables](#core-template-variables)
- [Model Configuration](#model-configuration)
- [Installation Guide](#installation-guide)
  - [Prerequisites](#prerequisites)
  - [Method 1: Pre-compiled Installation](#method-1-pre-compiled-installation-recommended)
  - [Method 2: Custom Build Installation](#method-2-custom-build-installation)
- [Local LLM Architecture](#local-llm-architecture)
- [Key Features](#key-features)
  - [Security & Privacy](#security--privacy)
  - [Productivity Tools](#productivity-tools)
  - [Performance](#performance)
- [Usage Workflow](#usage-workflow)
- [Screenshots](#screenshots)
- [Support Development](#support-development)
- [License & Attribution](#license--attribution)
- [Community & Feedback](#community--feedback)


## Overview

Suite-o-llama is a professional-grade Burp Suite extension that seamlessly integrates local Ollama LLM capabilities into your web security testing workflow. Designed specifically for penetration testers and bug bounty hunters, this tool transforms traditional security testing by adding AI-powered analysis and payload generation directly within Burp Suite's interface.

## Deep Burp Suite Integration

The extension integrates comprehensively across Burp Suite's ecosystem:

### Multi-Tab Integration
- **Main Tab**: Dedicated "Suite-o-llama" tab for comprehensive analysis and payload generation
- **Repeater Sub-tabs**: "Suite-o-llama AI" tabs appear automatically for both request and response analysis
- **Proxy Context Menu and Sub-tabs**: Right-click any request in Proxy history → "Send to Suite-o-llama". Also have a sub-tab of suite-o-llama AI in proxy-interception to generate payloads.
- **Settings Tab**: Dedicated configuration panel for Ollama connection and model settings
- **Prompts Ready**: Core variables can be used in manual prompts across all Burp modules

### Core Template Variables
Use these powerful variables directly in your manual prompts within any Burp sub-tab:
- `{{full_request}}` - Complete HTTP request (automatically redacted for security)
- `{{full_response}}` - Complete HTTP response for analysis
- `{{method}}` - HTTP method (GET, POST, PUT, DELETE)
- `{{url}}` - Target URL with full path
- `{{headers}}` - Request headers with privacy controls
- `{{body}}` - Request body content

## Model Configuration

Suite-o-llama is pre-configured with two specialized Ollama models optimized for penetration testing:

1. **Analysis Model**: `qwen2.5:7b-instruct` - Specialized in vulnerability analysis and security assessment
2. **Payload Model**: `qwen2.5-coder:7b` - Optimized for payload generation and exploit code

**Custom Model Support**: While configured for these base models, advanced users can modify the source code to use higher-capacity models or different architectures. Customization requires manual compilation using the provided build script `suite.sh`.

## Installation Guide

### Prerequisites
- **Ollama Running**: Ensure Ollama is installed and running (`ollama serve`)
- **Java**: openjdk21
- **Models Available**: Pull required models:
  ```bash
  ollama pull qwen2.5:7b-instruct
  ollama pull qwen2.5-coder:7b
- **Burp Suite**: Professional or Community Edition as of Jan 2026 (at the time of creating repository) or later.

### Method 1: Pre-compiled Installation recommended

1. **Download**: Get stable release of `suite-o-llama.jar` from the [Releases page](https://github.com/BerserkiKun/suite-o-llama/releases)
2. **Install in Burp**:
   ```bash
   Burp Suite → Extender → Extensions
   Click "Add" → Select the JAR file
   Make sure JAVA is selected
3. **Load Dependencies**: Load any additional required JAR files if prompted
4. **Configure**: Go to "Suite-o-llama Settings" tab and verify connection. Make sure your ollama is installed and up.
   ```bash
   # Check ollama health at http://localhost:11434 or http://127.0.0.1:11434
   # if it is not running then try this to start ollama
   ollama serve

### Method 2: Custom Build Installation

For custom modifications:

1. **Clone Repository**: 
   ```bash
   git clone https://github.com/berserkikun/suite-o-llama.git
   cd suite-o-llama

2. **Modify Files**:
   - Edit `suite.sh` for your system paths
   - Modify Java files for custom models/features
   - Adjust `ExtensionState.java` for different defaults

3. **Build**:
   ```bash
   chmod +x suite.sh
   ./suite.sh
*Note: Build script `suite.sh` works on macOS and Linux only. But you might need to change paths in the script file.*

4. **Install**: Load the generated JAR from `dist/` directory into Burp

## Local LLM Architecture

**Important**: Suite-o-llama works exclusively with your **local Ollama instance**:

- **Complete Privacy**: All data stays on your machine, nothing goes out
- **No Cloud Services**: No ChatGPT, Gemini, Claude, or other cloud APIs
- **No Subscriptions**: Zero API costs or usage fees
- **Offline Ready**: Works without internet connection

This ensures sensitive target data never leaves your environment, perfect for confidential security engagements.

## Key Features

### Security & Privacy
- Auto-redaction of Authorization headers and Cookies, this can be changed in suite-o-llama setting page.
- Configurable context size limits
- 100% local processing

### Productivity Tools
- Async processing with cancellation
- Pre-built security analysis prompts which can be manually adjusted
- Request/response context awareness with `variables`

### Performance
- Smart payload caching
- Rate-limited autocomplete
- Efficient background threading

## Usage Workflow

1. **Capture**: Proxy traffic through Burp
2. **Send**: Right-click → "Send to Suite-o-llama"
3. **Analyze**: Use preset or custom prompts
4. **Generate**: Write custom prompts for payload suggestions
5. **Test**: Send payloads directly from interface
6. **Iterate**: Analyze responses for sensitive data leakage etc

## Screenshots
<img width="1470" height="852" alt="img4 burp" src="https://github.com/user-attachments/assets/a81528e5-d050-47f4-8c3a-0ab28ad49d01" />
<img width="1470" height="781" alt="img5 burp" src="https://github.com/user-attachments/assets/feb03089-c456-4955-9bfa-1f4d1c69b139" />
<img width="1437" height="851" alt="img6 urp" src="https://github.com/user-attachments/assets/d46badd5-d402-410e-8f27-dd230c9b1979" />
<img width="2940" height="1706" alt="img 7" src="https://github.com/user-attachments/assets/1c8e1cb0-c1a2-47c1-b0dc-a13a4c7ed1b6" />
<img width="2940" height="1758" alt="img3" src="https://github.com/user-attachments/assets/3c81b90a-d142-4852-b3a6-725492624e1f" />


## Support Development

If Suite-o-llama helps your security testing, consider supporting its development:

**Support Links**:
- ☕ **Ko-fi**: [https://ko-fi.com/berserkikun](https://ko-fi.com/berserkikun)
- 💰 **PayPal**: [https://paypal.me/Berserk623](https://paypal.me/Berserk623)

Your support helps maintain the project and add new features.

---

## License & Attribution

Please respect the following:
- **Do not re-upload or repackage** as your own work
- **Do not remove attribution** or authorship credits
- **If you create a port in another language**, link back to this repository
- **Modifications are encouraged** but maintain clear attribution

## Community & Feedback

Community feedback is welcome. The local-first design ensures you can use Suite-o-llama confidently in sensitive environments while benefiting from AI-assisted security testing.

---

**Transform your penetration testing with AI-powered analysis while keeping complete control over your data.**
