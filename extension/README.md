# Testudo Browser Extension

🛡️ **Shield your wallet from malicious EIP-7702 delegations**

## What it does

Testudo intercepts EIP-7702 authorization signature requests and analyzes the delegate contract before you sign. It detects:

- ✅ Known malicious contracts (database lookup)
- ✅ ETH auto-forwarders (SELFBALANCE + CALL pattern)
- ✅ DELEGATECALL usage (arbitrary code execution)
- ✅ SELFDESTRUCT patterns (post-drain cleanup)
- ✅ Unlimited token approvals (max uint256)

## Quick Start

### 1. Install dependencies

```bash
npm install
```

### 2. Build the extension

```bash
npm run build
```

### 3. Load in Chrome

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `dist/` folder

### 4. Test it

Visit any dApp that uses EIP-7702 delegations. When a signature request is detected, Testudo will:

- **CRITICAL/HIGH risk**: Show blocking modal with threats
- **MEDIUM risk**: Show toast notification
- **LOW risk**: Allow silently

## Development

Watch mode (auto-rebuild on changes):

```bash
npm run watch
```

## Project Structure

```
testudo-extension/
├── manifest.json      # Chrome extension config
├── src/
│   ├── injected.ts    # Intercepts window.ethereum (page context)
│   ├── content.ts     # Bridge between page and extension
│   ├── background.ts  # Analysis engine (service worker)
│   └── popup.ts       # Popup UI logic
├── popup.html         # Extension popup
├── build.js           # esbuild script
└── dist/              # Built extension (load this in Chrome)
```

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  PHISHING SITE          TESTUDO EXTENSION                   │
│                                                             │
│  "Claim airdrop!"       ┌─────────────────────────────────┐ │
│        │                │  1. Intercept eth_signTypedData  │ │
│        ▼                │  2. Detect Authorization type    │ │
│  MetaMask popup ──────▶ │  3. Extract delegate address     │ │
│                         │  4. Fetch bytecode via RPC       │ │
│                         │  5. Run pattern detection        │ │
│                         │  6. Show warning if dangerous    │ │
│                         └─────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Testing with known malicious contract

The extension will detect this known malicious address:

```
0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b
```

This is a real ETH auto-forwarder that stole $2.3M+.

## Adding to your dApp (API coming soon)

```javascript
// Future: REST API for dApp integration
const response = await fetch('https://api.testudo.io/analyze', {
  method: 'POST',
  body: JSON.stringify({ address: delegateAddress }),
});

const { risk, threats } = await response.json();
```

## License

MIT
