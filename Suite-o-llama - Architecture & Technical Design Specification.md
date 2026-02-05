\# \*\*Suite-o-llama v2.2.1 - Official Project Documentation\*\*



\## Table of Contents

\- \[1. Executive Summary](#1-executive-summary)

\- \[2. System Architecture](#2-system-architecture)

&nbsp; - \[2.1 High-Level Architecture Diagram](#21-high-level-architecture-diagram)

&nbsp; - \[2.2 Component Architecture](#22-component-architecture)

&nbsp; - \[2.3 Data Flow Architecture](#23-data-flow-architecture)

\- \[3. Detailed Component Specifications](#3-detailed-component-specifications)

&nbsp; - \[3.1 Core Infrastructure Components](#31-core-infrastructure-components)

&nbsp; - \[3.2 UI Layer Components](#32-ui-layer-components)

&nbsp; - \[3.3 Repeater Integration Components](#33-repeater-integration-components)

&nbsp; - \[3.4 AI/LLM Engine Components](#34-aillm-engine-components)

\- \[4. Process Flows](#4-process-flows)

&nbsp; - \[4.1 Extension Initialization Flow](#41-extension-initialization-flow)

&nbsp; - \[4.2 Request Analysis Flow](#42-request-analysis-flow)

&nbsp; - \[4.3 Auto-complete Flow](#43-auto-complete-flow)

&nbsp; - \[4.4 Repeater Integration Flow](#44-repeater-integration-flow)

\- \[5. Feature Requirements \& Specifications](#5-feature-requirements--specifications)

&nbsp; - \[5.1 Core Functional Requirements](#51-core-functional-requirements)

&nbsp; - \[5.2 Non-Functional Requirements](#52-non-functional-requirements)

&nbsp; - \[5.3 Technical Constraints](#53-technical-constraints)

\- \[6. Implementation Guidance](#6-implementation-guidance)

&nbsp; - \[6.1 Development Environment Setup](#61-development-environment-setup)

&nbsp; - \[6.2 Build Process](#62-build-process)

&nbsp; - \[6.3 Installation \& Deployment](#63-installation--deployment)

&nbsp; - \[6.4 Testing Strategy](#64-testing-strategy)

&nbsp; - \[6.5 Debugging \& Troubleshooting](#65-debugging--troubleshooting)

&nbsp; - \[6.6 Extension Points for Customization](#66-extension-points-for-customization)

\- \[7. Architectural Decisions \& Rationale](#7-architectural-decisions--rationale)

\- \[8. Security Considerations](#8-security-considerations)

\- \[9. Future Enhancement Considerations](#9-future-enhancement-considerations)

\- \[10. Conclusion](#10-conclusion)



\## \*\*1. Executive Summary\*\*



\*\*Suite-o-llama\*\* is a sophisticated Burp Suite Professional extension that integrates local LLM (Ollama) capabilities directly into the security testing workflow. The extension provides AI-assisted analysis of HTTP traffic, automated payload generation, and a multi-tab workspace for efficient security assessment.



\*\*Current Version\*\*: 2.2.1  

\*\*Primary Purpose\*\*: Enhance manual security testing with AI-powered insights while maintaining full local processing for privacy and control.



---



\## \*\*2. System Architecture\*\*



\### \*\*2.1 High-Level Architecture Diagram\*\*



```

┌─────────────────────────────────────────────────────────────────┐

│                       BURP SUITE PROFESSIONAL                    │

├─────────────────────────────────────────────────────────────────┤

│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │

│  │   Proxy     │  │  Repeater   │  │       Intruder          │  │

│  └──────┬──────┘  └──────┬──────┘  └─────────────────────────┘  │

│         │                │                                       │

│  ┌──────▼──────┐  ┌─────▼─────┐                                 │

│  │ Context Menu│  │AI Analysis │                                 │

│  │  Factory    │  │   Tabs     │                                 │

│  └──────┬──────┘  └────────────┘                                 │

│         │                │                                       │

├─────────┼────────────────┼───────────────────────────────────────┤

│         │                │                                       │

│  ┌──────▼────────────────▼──────┐                                │

│  │    SUITE-O-LLAMA EXTENSION   │                                │

│  ├──────────────────────────────┤                                │

│  │  ┌────────────────────────┐  │                                │

│  │  │    Multi-Tab Manager   │◄─┼─────────────────┐              │

│  │  │    (TabManager)        │  │                 │              │

│  │  └──────────┬─────────────┘  │                 │              │

│  │             │                 │                 │              │

│  │  ┌──────────▼─────────────┐  │  ┌──────────────▼──────┐      │

│  │  │ Individual Tab Panel   │  │  │   Settings \& Config │      │

│  │  │   (MainTabPanel)       │  │  │    (SettingsTab)    │      │

│  │  └──────────┬─────────────┘  │  └─────────────────────┘      │

│  │             │                 │                 │              │

│  │  ┌──────────▼─────────────┐  │  ┌──────────────▼──────┐      │

│  │  │   AI Analysis Engine   │  │  │   Update Checker    │      │

│  │  │   (PromptEngine)       │  │  │  (UpdateChecker)    │      │

│  │  └──────────┬─────────────┘  │  └─────────────────────┘      │

│  │             │                 │                                │

│  │  ┌──────────▼─────────────┐  │                                │

│  │  │    LLM Client Layer    │  │                                │

│  │  │    (OllamaClient)      │  │                                │

│  │  └──────────┬─────────────┘  │                                │

│  │             │                 │                                │

│  └─────────────┼─────────────────┘                                │

│                │                                                  │

├────────────────┼──────────────────────────────────────────────────┤

│                │                                                  │

│        ┌───────▼────────┐                                        │

│        │   OLLAMA API   │                                        │

│        │   (Localhost)  │                                        │

│        └────────────────┘                                        │

│                │                                                  │

│        ┌───────▼────────┐                                        │

│        │  Local LLMs    │                                        │

│        │ (qwen2.5, etc.)│                                        │

│        └────────────────┘                                        │

└──────────────────────────────────────────────────────────────────┘

```



\### \*\*2.2 Component Architecture\*\*



```

┌─────────────────────────────────────────────────────────────┐

│                    CORE INFRASTRUCTURE                       │

├─────────────────────────────────────────────────────────────┤

│  BurpExtender (Entry Point)                                 │

│  ExtensionState (Configuration \& State Manager)             │

│  RequestContext (Data Container)                            │

│  AutocompleteContext (Lightweight Wrapper)                  │

│  ContextTrimmer (Content Size Manager)                      │

├─────────────────────────────────────────────────────────────┤

│                    UI LAYER                                  │

├─────────────────────────────────────────────────────────────┤

│  TabManager (Multi-Tab Workspace)                           │

│  MainTabPanel (Individual Tab Implementation)               │

│  SettingsTab (Configuration UI)                             │

│  PromptManagerDialog (Saved Prompts Manager)                │

│  ContextMenuFactory (Burp Context Menu Integration)         │

├─────────────────────────────────────────────────────────────┤

│                    REPEATER INTEGRATION                      │

├─────────────────────────────────────────────────────────────┤

│  MessageEditorTabFactory (Tab Factory)                      │

│  RepeaterAITab (Request Analysis Tab)                       │

│  RepeaterAIResponseTab (Response Analysis Tab)              │

├─────────────────────────────────────────────────────────────┤

│                    AI/LLM ENGINE                             │

├─────────────────────────────────────────────────────────────┤

│  OllamaClient (LLM Communication)                           │

│  PromptEngine (Template Processing)                         │

│  ConversationSession (Multi-turn Dialogue)                  │

│  AutocompleteEngine (Payload Generation)                    │

└─────────────────────────────────────────────────────────────┘

```



\### \*\*2.3 Data Flow Architecture\*\*



```

HTTP Request/Response in Burp

&nbsp;       │

&nbsp;       ▼

┌───────────────┐

│ Context Menu  │  (Right-click → "Send to Suite-o-llama")

└───────┬───────┘

&nbsp;       │

&nbsp;       ▼

┌───────────────┐

│ Tab Manager   │  → Smart tab allocation \& creation

└───────┬───────┘

&nbsp;       │

&nbsp;       ▼

┌───────────────┐

│ MainTabPanel  │  → Request/Response editing \& analysis

└───────┬───────┘

&nbsp;       │

&nbsp;       ├────────────────────────────────────┐

&nbsp;       │                                    │

&nbsp;       ▼                                    ▼

┌───────────────┐                 ┌──────────────────┐

│ Send to Server│                 │  Send to LLM     │

│ (Re-issue req)│                 │ (AI Analysis)    │

└───────┬───────┘                 └────────┬─────────┘

&nbsp;       │                                    │

&nbsp;       ▼                                    ▼

┌───────────────┐                 ┌──────────────────┐

│ Burp's HTTP   │                 │  Prompt Engine   │

│ Engine        │                 │  (Template +     │

└───────┬───────┘                 │   Variables)     │

&nbsp;       │                          └────────┬─────────┘

&nbsp;       ▼                                    │

┌───────────────┐                 ┌──────────────────┐

│ Response      │                 │  Ollama Client   │

│ Processing    │                 │  (API Call)      │

└───────┬───────┘                 └────────┬─────────┘

&nbsp;       │                                    │

&nbsp;       ▼                                    ▼

┌─────────────────────────────┐    ┌──────────────────┐

│ Update UI with Response     │    │  Parse \& Display │

│ and Timing Information      │    │  LLM Response    │

└─────────────────────────────┘    └──────────────────┘

```



---



\## \*\*3. Detailed Component Specifications\*\*



\### \*\*3.1 Core Infrastructure Components\*\*



\#### \*\*3.1.1 BurpExtender.java\*\*

\*\*Purpose\*\*: Main entry point implementing Burp's extension interface

\*\*Responsibilities\*\*:

\- Initialize extension on Burp startup

\- Register all UI components and factories

\- Manage extension lifecycle

\- Set extension name and version



\*\*Key Methods\*\*:

\- `registerExtenderCallbacks()` - Primary initialization

\- `getTabCaption()` - Returns "Suite-o-llama"

\- `getUiComponent()` - Returns main UI component



\#### \*\*3.1.2 ExtensionState.java\*\*

\*\*Purpose\*\*: Centralized configuration and state management

\*\*Design Pattern\*\*: Singleton (via dependency injection)



\*\*Configuration Categories\*\*:

1\. \*\*Ollama Connection\*\*

&nbsp;  - Endpoint URL (default: `http://127.0.0.1:11434`)

&nbsp;  - Analysis model (default: `qwen2.5:7b-instruct`)

&nbsp;  - Payload model (default: `qwen2.5-coder:7b`)



2\. \*\*Generation Parameters\*\*

&nbsp;  - Temperature (0.0-2.0, default: 0.7)

&nbsp;  - Max tokens (128-16384, default: 4096)

&nbsp;  - Max context size (1024-65536 chars, default: 16384)



3\. \*\*Security \& Privacy\*\*

&nbsp;  - Redact authorization headers (default: true)

&nbsp;  - Redact cookies (default: true)



4\. \*\*Saved Prompts\*\*

&nbsp;  - Custom prompt templates with variable substitution

&nbsp;  - Persistent storage via Java Preferences API



\*\*Persistence Mechanism\*\*: Java Preferences API → `HKEY\_CURRENT\_USER\\Software\\JavaSoft\\Prefs\\burp`



\### \*\*3.2 UI Layer Components\*\*



\#### \*\*3.2.1 TabManager.java\*\*

\*\*Purpose\*\*: Repeater-style multi-tab workspace management

\*\*Key Innovations\*\*:

\- \*\*Smart Tab Allocation\*\*: Reuses empty tabs before creating new ones

\- \*\*Drag-and-Drop Reordering\*\*: Custom implementation with auto-scroll

\- \*\*Tab Context Menu\*\*: Right-click operations (close, rename, close others)

\- \*\*"+" Button\*\*: Consistent with Burp's UI patterns



\*\*Tab States\*\*:

1\. \*\*Initial Empty Tab\*\*: First tab created on startup (special reuse flag)

2\. \*\*Active Tab\*\*: Currently selected tab with content

3\. \*\*Empty Tab\*\*: Tab with no content (eligible for reuse)



\*\*Algorithm for Request Loading\*\*:

```pseudo

procedure loadRequestInSmartTab(request, service):

&nbsp;   for each tab (excluding "+" button):

&nbsp;       if tab is initial empty tab:

&nbsp;           reuse tab for request

&nbsp;           clear initial empty flag

&nbsp;           return

&nbsp;   

&nbsp;   if current tab is empty (no content):

&nbsp;       reuse current tab

&nbsp;   else:

&nbsp;       create new tab

```



\#### \*\*3.2.2 MainTabPanel.java\*\*

\*\*Purpose\*\*: Individual tab implementation with full editing capabilities

\*\*Implements\*\*: `IMessageEditorController` (Burp interface)



\*\*UI Layout\*\*:

```

┌─────────────────────────────────────────────────┐

│ Request Editor          │ Response Editor       │

├─────────────────────────────────────────────────┤

│ Prompt Area (with template variables)           │

│ LLM Response Area                               │

├─────────────────────────────────────────────────┤

│ \[Clear]\[Send to Server]\[Send to LLM]\[Cancel]    │

│ \[GitHub]\[Support Development]                   │

└─────────────────────────────────────────────────┘

```



\*\*Features\*\*:

\- Full request/response editing (Burp's message editor)

\- Auto-complete (Ctrl+Space) for parameter values

\- Server response time display

\- Conversation history across LLM interactions

\- Request re-issuing to server



\#### \*\*3.2.3 SettingsTab.java\*\*

\*\*Purpose\*\*: Comprehensive configuration interface



\*\*Sections\*\*:

1\. \*\*Ollama Connection\*\*: Endpoint configuration with test button

2\. \*\*Model Configuration\*\*: Analysis/payload models, temperature, token limits

3\. \*\*Security \& Privacy\*\*: Header redaction settings

4\. \*\*Available Models\*\*: Dynamic model browser with refresh

5\. \*\*Update Checking\*\*: GitHub integration for version updates



\### \*\*3.3 Repeater Integration Components\*\*



\#### \*\*3.3.1 MessageEditorTabFactory.java\*\*

\*\*Purpose\*\*: Factory for creating AI analysis tabs in Burp Repeater

\*\*Design Pattern\*\*: Factory + State Preservation



\*\*State Preservation Mechanism\*\*:

\- Uses `WeakHashMap` to track last tab state per controller

\- Transfers non-default prompt and response between tab instances

\- Preserves user work across request/response updates



\#### \*\*3.3.2 RepeaterAITab.java \& RepeaterAIResponseTab.java\*\*

\*\*Purpose\*\*: Specialized tabs for request and response analysis in Repeater



\*\*Differences\*\*:

\- \*\*RepeaterAITab\*\*: For request analysis, includes model selector

\- \*\*RepeaterAIResponseTab\*\*: For response analysis, includes "Include Request" checkbox



\*\*State Management\*\*:

\- Per-tab conversation sessions

\- Persistent prompt/response across SEND operations

\- Automatic cleanup on tab closure



\### \*\*3.4 AI/LLM Engine Components\*\*



\#### \*\*3.4.1 OllamaClient.java\*\*

\*\*Purpose\*\*: Communication layer with Ollama API

\*\*Version 2.2.0 Enhancements\*\*: Streaming, cancellation, multi-threading



\*\*Threading Model\*\*:

\- Fixed thread pool (3 workers)

\- Async generation with callback interface

\- Immediate cancellation via HTTP connection disconnect



\*\*API Integration\*\*:

\- Endpoint: `{endpoint}/api/generate`

\- Method: POST with JSON payload

\- Streaming: Enabled for progressive response



\*\*ResponseCallback Interface\*\*:

```java

interface ResponseCallback {

&nbsp;   void onSuccess(String response, long timeMs, int estimatedTokens);

&nbsp;   void onError(String error);

&nbsp;   void onCancelled(long cancelTimeMs);  // Added in v2.2.0

}

```



\#### \*\*3.4.2 PromptEngine.java\*\*

\*\*Purpose\*\*: Template processing and variable substitution engine



\*\*Available Variables\*\*:

```

{{method}}          - HTTP method (GET, POST, etc.)

{{url}}             - Full URL

{{req\_headers}}     - Request headers (redacted if configured)

{{req\_body}}        - Request body

{{full\_request}}    - Complete HTTP request

{{res\_headers}}     - Response headers (if available)

{{res\_body}}        - Response body (if available)

{{full\_response}}   - Complete HTTP response (if available)

```



\*\*Security Processing\*\*:

\- Header redaction based on configuration

\- Context size limiting

\- Priority-based trimming (headers > body)



\#### \*\*3.4.3 AutocompleteEngine.java\*\*

\*\*Purpose\*\*: Real-time security payload generation

\*\*Use Case\*\*: Ctrl+Space in prompt area for parameter-specific payloads



\*\*Workflow\*\*:

1\. Extract parameter context around cursor

2\. Check cache (key: `url:paramContext.hashCode()`)

3\. Rate limit check (Semaphore with 3 permits)

4\. Generate in background via single-thread executor

5\. Parse LLM response into clean payload array

6\. Insert first suggestion



\*\*Generation Prompt\*\*:

```

"Generate 5 security testing payloads for this parameter context:

{paramContext}



Output format: one payload per line, no explanations.

Focus on: SQLi, XSS, command injection."

```



\#### \*\*3.4.4 ConversationSession.java\*\*

\*\*Purpose\*\*: Multi-turn conversation management

\*\*Design\*\*: Linked list of exchanges with timeout management



\*\*Features\*\*:

\- 30-exchange history limit

\- 10-minute inactivity timeout

\- Automatic cleanup via scheduled executor

\- Conversation context building for LLM prompts



---



\## \*\*4. Process Flows\*\*



\### \*\*4.1 Extension Initialization Flow\*\*



```

Burp Suite Startup

&nbsp;       ↓

load Suite-o-llama.jar

&nbsp;       ↓

BurpExtender.registerExtenderCallbacks()

&nbsp;       ↓

Create ExtensionState (load saved settings)

&nbsp;       ↓

SwingUtilities.invokeLater() \[EDT]

&nbsp;       ↓

Initialize Core Components:

&nbsp; - OllamaClient

&nbsp; - PromptEngine  

&nbsp; - AutocompleteEngine

&nbsp; - TabManager

&nbsp;       ↓

Register UI Components:

&nbsp; - Add Suite-o-llama tab (TabManager)

&nbsp; - Add Settings tab

&nbsp; - Register context menu factory

&nbsp; - Register message editor tab factory

&nbsp;       ↓

Create Initial Empty Tab

&nbsp;       ↓

Extension Ready

```



\### \*\*4.2 Request Analysis Flow\*\*



```

User right-clicks request in Burp

&nbsp;       ↓

ContextMenuFactory.createMenuItems()

&nbsp;       ↓

"Send to Suite-o-llama" clicked

&nbsp;       ↓

TabManager.loadRequestInSmartTab()

&nbsp;       ↓

Check for initial empty tab → Reuse if found

&nbsp;       ↓

Else check current tab content → Reuse if empty

&nbsp;       ↓

Else create new tab

&nbsp;       ↓

MainTabPanel.loadRequestOnly()

&nbsp;       ↓

Request loaded in editor, response cleared

&nbsp;       ↓

User enters prompt (with variables)

&nbsp;       ↓

User clicks "Send to LLM"

&nbsp;       ↓

PromptEngine.processTemplate()

&nbsp;       ↓

ConversationSession.buildConversationPrompt() \[if exists]

&nbsp;       ↓

OllamaClient.generateAsync()

&nbsp;       ↓

UI: Show "Analyzing..." with cancel option

&nbsp;       ↓

On Success: Display formatted response

&nbsp;       ↓

ConversationSession.addExchange() \[for history]

```



\### \*\*4.3 Auto-complete Flow\*\*



```

User types in prompt area

&nbsp;       ↓

User presses Ctrl+Space

&nbsp;       ↓

MainTabPanel.showAutocomplete()

&nbsp;       ↓

Extract parameter context around cursor

&nbsp;       ↓

AutocompleteEngine.generatePayloads()

&nbsp;       ↓

Check cache → Return if cached

&nbsp;       ↓

Rate limit check → Skip if busy

&nbsp;       ↓

Generate payloads in background

&nbsp;       ↓

Parse LLM response into clean array

&nbsp;       ↓

Cache results (url:paramContext.hashCode())

&nbsp;       ↓

Insert first payload into text area

```



\### \*\*4.4 Repeater Integration Flow\*\*



```

User opens request in Burp Repeater

&nbsp;       ↓

MessageEditorTabFactory.createNewInstance()

&nbsp;       ↓

Check for previous tab state (WeakHashMap)

&nbsp;       ↓

Create RepeaterAITab with preserved state

&nbsp;       ↓

User clicks "Analyze with Ollama"

&nbsp;       ↓

Check Ollama health and model availability

&nbsp;       ↓

Generate with conversation context

&nbsp;       ↓

Preserve prompt/response for next update

&nbsp;       ↓

User clicks SEND (Ctrl+R)

&nbsp;       ↓

New response received

&nbsp;       ↓

RepeaterAITab.setMessage() preserves LLM state

```



---



\## \*\*5. Feature Requirements \& Specifications\*\*



\### \*\*5.1 Core Functional Requirements\*\*



\#### \*\*FR-001: Multi-Tab Workspace\*\*

\- \*\*Requirement\*\*: Provide Repeater-style multi-tab interface

\- \*\*Specifications\*\*:

&nbsp; - "+" button for new tab creation

&nbsp; - Tab drag-and-drop reordering

&nbsp; - Right-click context menu

&nbsp; - Smart tab reuse algorithm

&nbsp; - Close buttons on each tab

\- \*\*Implementation\*\*: `TabManager.java`



\#### \*\*FR-002: AI-Powered Analysis\*\*

\- \*\*Requirement\*\*: Integrate local LLM for security analysis

\- \*\*Specifications\*\*:

&nbsp; - Support multiple models (analysis vs payload)

&nbsp; - Template variable substitution

&nbsp; - Conversation history across interactions

&nbsp; - Configurable generation parameters

\- \*\*Implementation\*\*: `OllamaClient.java`, `PromptEngine.java`, `ConversationSession.java`



\#### \*\*FR-003: Auto-complete Payload Generation\*\*

\- \*\*Requirement\*\*: Real-time payload suggestions

\- \*\*Specifications\*\*:

&nbsp; - Ctrl+Space trigger

&nbsp; - Context-aware generation

&nbsp; - Caching for performance

&nbsp; - Rate limiting (3 concurrent)

\- \*\*Implementation\*\*: `AutocompleteEngine.java`



\#### \*\*FR-004: Burp Integration\*\*

\- \*\*Requirement\*\*: Seamless integration with Burp Suite

\- \*\*Specifications\*\*:

&nbsp; - Context menu in Proxy/Repeater

&nbsp; - Message editor tabs in Repeater

&nbsp; - IMessageEditorController implementation

&nbsp; - Consistent UI patterns with Burp

\- \*\*Implementation\*\*: `ContextMenuFactory.java`, `MessageEditorTabFactory.java`



\#### \*\*FR-005: Configuration Management\*\*

\- \*\*Requirement\*\*: Comprehensive settings system

\- \*\*Specifications\*\*:

&nbsp; - Ollama connection settings

&nbsp; - Model configuration

&nbsp; - Security preferences

&nbsp; - Saved prompts management

&nbsp; - Persistent storage

\- \*\*Implementation\*\*: `ExtensionState.java`, `SettingsTab.java`



\### \*\*5.2 Non-Functional Requirements\*\*



\#### \*\*NFR-001: Performance\*\*

\- Background processing for LLM calls

\- Caching for auto-complete

\- Rate limiting to prevent overload

\- Efficient tab management



\#### \*\*NFR-002: Reliability\*\*

\- Health checks before LLM calls

\- Graceful error handling

\- State preservation across operations

\- Timeout management for conversations



\#### \*\*NFR-003: Security\*\*

\- Local LLM processing (no external APIs)

\- Configurable header redaction

\- No sensitive data leakage

\- Secure storage of settings



\#### \*\*NFR-004: Usability\*\*

\- Consistent with Burp UI patterns

\- Intuitive tab management

\- Clear error messages

\- Comprehensive tooltips



\#### \*\*NFR-005: Maintainability\*\*

\- Modular component design

\- Clear separation of concerns

\- Comprehensive logging

\- Update checking mechanism



\### \*\*5.3 Technical Constraints\*\*



\#### \*\*TC-001: Burp Suite Compatibility\*\*

\- Must implement Burp extension interfaces

\- Must work within Burp's classloader

\- Must respect Burp's UI threading (EDT)

\- Must coexist with other extensions



\#### \*\*TC-002: Ollama Dependency\*\*

\- Requires local Ollama installation

\- Requires specific model availability

\- Network connectivity to localhost:11434

\- Model compatibility with prompt formats



\#### \*\*TC-003: Java Version\*\*

\- Compatible with Burp's Java runtime

\- No external library dependencies (except JSON)

\- Must work with Burp's restricted environment



---



\## \*\*6. Implementation Guidance\*\*



\### \*\*6.1 Development Environment Setup\*\*



\#### \*\*Prerequisites\*\*:

1\. \*\*Burp Suite Professional\*\* (latest version)

2\. \*\*Java Development Kit\*\* (JDK 21 or later)

3\. \*\*Ollama\*\* installed and running locally

4\. \*\*Recommended models\*\*:

&nbsp;  ```bash

&nbsp;  ollama pull qwen2.5:7b-instruct

&nbsp;  ollama pull qwen2.5-coder:7b

&nbsp;  ```



\#### \*\*Project Structure\*\*:

```

suite-o-llama/

├── src/

│   └── burp/

│       ├── BurpExtender.java          # Entry point

│       ├── ExtensionState.java        # Configuration

│       ├── TabManager.java            # Main UI

│       ├── MainTabPanel.java          # Tab implementation

│       ├── SettingsTab.java           # Settings UI

│       ├── OllamaClient.java          # LLM communication

│       ├── PromptEngine.java          # Template processing

│       ├── AutocompleteEngine.java    # Payload generation

│       ├── ConversationSession.java   # Chat history

│       ├── RepeaterAITab.java         # Repeater integration

│       ├── RepeaterAIResponseTab.java # Response analysis

│       ├── MessageEditorTabFactory.java # Tab factory

│       ├── ContextMenuFactory.java    # Context menu

│       ├── RequestContext.java        # Data container

│       ├── AutocompleteContext.java   # Lightweight wrapper

│       ├── ContextTrimmer.java        # Content trimming

│       ├── PromptManagerDialog.java   # Prompt management

│       └── UpdateChecker.java         # Version checking

```



\### \*\*6.2 Build Process\*\*



\#### \*\*Build Command\*\*:

```bash

\# Go into directory and run suite.sh file

./suite.sh

```



\#### \*\*Output\*\*:

\- `Suite-o-llama.jar` (complete extension)



\### \*\*6.3 Installation \& Deployment\*\*



\#### \*\*Installation Steps\*\*:

1\. Start Burp Suite Professional

2\. Navigate to Extender → Extensions

3\. Click "Add"

4\. Select "Java" as extension type

5\. Browse and select `Suite-o-llama.jar`

6\. Extension loads automatically



\#### \*\*Initial Configuration\*\*:

1\. Go to "Suite-o-llama Settings" tab

2\. Verify Ollama endpoint (`http://127.0.0.1:11434`)

3\. Test connection

4\. Configure preferred models

5\. Adjust security settings as needed



\### \*\*6.4 Testing Strategy\*\*



\#### \*\*Unit Testing Areas\*\*:

1\. \*\*PromptEngine\*\*: Template variable substitution

2\. \*\*ContextTrimmer\*\*: Content size management

3\. \*\*ExtensionState\*\*: Configuration persistence

4\. \*\*TabManager\*\*: Tab allocation algorithms



\#### \*\*Integration Testing\*\*:

1\. Burp context menu integration

2\. Repeater tab functionality

3\. Ollama API communication

4\. UI responsiveness and threading



\#### \*\*Manual Testing Scenarios\*\*:

1\. Right-click request → Send to Suite-o-llama

2\. Multiple tab creation and management

3\. LLM analysis with different prompt templates

4\. Auto-complete functionality

5\. Settings persistence across restarts



\### \*\*6.5 Debugging \& Troubleshooting\*\*



\#### \*\*Common Issues\*\*:



1\. \*\*Ollama Connection Failed\*\*:

&nbsp;  - Verify `ollama serve` is running

&nbsp;  - Check endpoint in settings

&nbsp;  - Test connection button



2\. \*\*Model Not Available\*\*:

&nbsp;  - Use `ollama pull <model-name>`

&nbsp;  - Refresh models in settings

&nbsp;  - Check model name spelling



3\. \*\*UI Freezing\*\*:

&nbsp;  - Check for long-running LLM calls

&nbsp;  - Use cancellation button

&nbsp;  - Verify threading (all UI updates on EDT)



4\. \*\*State Not Preserved\*\*:

&nbsp;  - Check Java Preferences permissions

&nbsp;  - Verify saved prompts format

&nbsp;  - Check for exceptions in stderr



\#### \*\*Logging Strategy\*\*:

\- \*\*stdout\*\*: General operational messages

\- \*\*stderr\*\*: Errors and exceptions

\- \*\*Burp's Event Log\*\*: Extension lifecycle events



\### \*\*6.6 Extension Points for Customization\*\*



\#### \*\*Custom Prompt Templates\*\*:

Users can create and save custom templates using the prompt manager dialog. Templates support variable substitution and can be shared between team members.



\#### \*\*Model Configuration\*\*:

Support for different LLM models can be added by:

1\. Installing the model locally via Ollama

2\. Updating model names in settings

3\. Adjusting temperature/token limits as needed



\#### \*\*Security Headers\*\*:

Additional headers can be added to redaction logic by modifying `PromptEngine.shouldRedactHeader()` method.



\#### \*\*Auto-complete Focus Areas\*\*:

The focus areas for payload generation (SQLi, XSS, command injection) can be modified in `AutocompleteEngine.generatePayloadsInternal()`.



---



\## \*\*7. Architectural Decisions \& Rationale\*\*



\### \*\*7.1 Multi-Tab vs Single-Tab Design\*\*

\*\*Decision\*\*: Implement Repeater-style multi-tab interface

\*\*Rationale\*\*:

\- Consistent with Burp Suite UI patterns

\- Allows parallel analysis of multiple requests

\- Better workflow for security testing

\- Tab reuse reduces cognitive load



\### \*\*7.2 Local LLM vs Cloud API\*\*

\*\*Decision\*\*: Use local Ollama installation

\*\*Rationale\*\*:

\- No data leaves the security tester's environment

\- No API costs or rate limits

\- Works in air-gapped environments

\- Full control over model selection



\### \*\*7.3 Conversation vs Single-Turn\*\*

\*\*Decision\*\*: Implement conversation history with timeouts

\*\*Rationale\*\*:

\- Enables follow-up questions and iterative analysis

\- Timeout prevents resource leaks

\- History limit prevents context overflow

\- Session-based for privacy



\### \*\*7.4 State Preservation Strategy\*\*

\*\*Decision\*\*: WeakHashMap + per-tab state

\*\*Rationale\*\*:

\- Preserves user work across operations

\- Automatic cleanup when tabs close

\- Memory efficient

\- Transparent to user



\### \*\*7.5 Threading Model\*\*

\*\*Decision\*\*: Fixed thread pool (3) + single-thread executors

\*\*Rationale\*\*:

\- Prevents overwhelming Ollama with concurrent requests

\- Separate threads for different operations

\- UI responsiveness maintained

\- Cancellation support implemented



---



\## \*\*8. Security Considerations\*\*



\### \*\*8.1 Data Privacy\*\*

\- All processing occurs locally

\- Configurable header redaction

\- No external API calls (except update checking)

\- Conversation history cleared on timeout



\### \*\*8.2 Configuration Security\*\*

\- Settings stored in user's local preferences

\- No hardcoded credentials

\- Redaction applied before LLM processing

\- User explicitly controls what data is sent to LLM



\### \*\*8.3 Operational Security\*\*

\- Health checks before LLM calls

\- Timeouts on all network operations

\- Graceful degradation on failures

\- Clear error messages without information leakage



---



\## \*\*9. Future Enhancement Considerations\*\*



\### \*\*9.1 Planned Evolution Path\*\*

1\. \*\*Additional Analysis Types\*\*: API spec analysis, business logic testing

2\. \*\*Team Collaboration\*\*: Shared prompt libraries, result sharing

3\. \*\*Integration Expansion\*\*: Scanner, Intruder, Collaborator integration

4\. \*\*Advanced Features\*\*: Automated testing workflows, report generation



\### \*\*9.2 Technical Debt Areas\*\*

1\. \*\*Error Handling\*\*: More granular error categorization

2\. \*\*Testing\*\*: Comprehensive test suite

3\. \*\*Documentation\*\*: API documentation for extension points

4\. \*\*Internationalization\*\*: Support for multiple languages



\### \*\*9.3 Scalability Considerations\*\*

\- Currently designed for individual security testers

\- Could be extended for team use with shared configurations

\- Model performance scales with local hardware

\- Memory usage managed via conversation limits



---



\## \*\*10. Conclusion\*\*



Suite-o-llama represents a sophisticated integration of local LLM capabilities into the Burp Suite security testing workflow. The architecture demonstrates careful consideration of security, usability, and performance, with particular attention to maintaining the privacy and control that security professionals require.



The extension's modular design, comprehensive feature set, and adherence to Burp's UI patterns make it a valuable tool for enhancing manual security testing with AI-powered insights while maintaining the tester's full control over the testing process.



\*\*Key Success Metrics\*\*:

\- Reduced time for vulnerability analysis

\- Improved payload generation efficiency

\- Enhanced testing consistency through saved prompts

\- Maintained data privacy through local processing

\- Seamless integration with existing Burp workflows

