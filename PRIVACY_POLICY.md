# Testudo Privacy Policy

**Last Updated**: 2026-02-16

Testudo is a browser extension that protects your wallet from malicious smart contract interactions. This policy explains what data the extension processes, what external services it communicates with, and why specific permissions are required.

## Data Processing

Testudo processes the following data **locally in your browser**:

- **Smart contract addresses** from transaction and signature requests intercepted by the extension
- **Typed data** from EIP-712 signature requests (to detect permits, approvals, and EIP-7702 delegations)
- **Message content** from personal_sign requests (to detect phishing patterns)

This data is processed in real time to determine risk levels. The extension does not collect, store, or transmit browsing history, personal information, or wallet balances.

## Local Storage

The extension stores the following data locally using `chrome.storage.local`:

- **Settings**: notification preferences
- **Scan history**: recent scan results (contract address, risk level, timestamp, originating site domain)
- **Statistics**: aggregate counts (scans performed, threats blocked)
- **Whitelist**: addresses you have explicitly marked as trusted, with the domain where whitelisting occurred

All locally stored data can be viewed and cleared from the extension's Settings page.

## External Services

The extension communicates with the following external services to perform threat analysis:

| Service | Domain | Purpose | Data Sent |
|---------|--------|---------|-----------|
| Testudo Threat API | `testudo-api-production.up.railway.app` | Look up known malicious addresses | Contract address being analyzed |
| Blockscout API | `eth.blockscout.com` | Look up contract deployer information | Contract address being analyzed |
| Safe Filter CDN | `pub-76c6347fe0fc49d7b1497bc741c11d24.r2.dev` | Download safe address filter set | No user data (static file download) |
| Ethereum RPC | `eth.llamarpc.com` | Fetch contract bytecode and token metadata | Contract address being analyzed |

**What is sent**: Only the smart contract address being analyzed is sent to external services. No wallet addresses, private keys, transaction amounts, browsing history, or personal information is transmitted.

**When requests are made**: External requests occur when Testudo analyzes wallet transaction/signature activity on a dApp page. The extension also makes periodic safe filter update requests (a static file download with no user data).

## Permissions

| Permission | Purpose |
|------------|---------|
| `storage` | Save settings, scan history, and whitelist locally on your device |
| `alarms` | Schedule periodic safe filter updates (downloading a static file of known-safe addresses) |
| `host_permissions` (4 pinned domains) | Required to communicate with the specific external services listed above. Only these exact domains are contacted. |
| `content_scripts` (all URLs) | Inject the security interception script that monitors wallet signature and transaction requests. See justification below. |
| `web_accessible_resources` (all URLs) | Load the injected security script and bundled font files into page context |

### Why content_scripts requires all URLs

Testudo must run on every webpage because:

1. **Malicious dApps can be hosted on any domain** — phishing sites and drainer contracts appear on new domains constantly. Limiting to specific sites would leave users unprotected.
2. **Legitimate dApps can be compromised** — even trusted sites may serve malicious signature requests via supply-chain attacks or frontend compromises.
3. **The extension only activates when a wallet interaction occurs** — the content script is lightweight and does not read, modify, or transmit any page content. It only intercepts Ethereum provider calls (`window.ethereum.request`).

### Fonts

Popup/options UI and warning modal typography use bundled local font files packaged inside the extension. No third-party font CDN requests are required.

### What the extension does NOT do

- Read or modify page content, forms, or DOM elements (beyond its own security modal)
- Track browsing history or page visits
- Access page content unrelated to wallet signature/transaction requests
- Send analytics, tracking, or telemetry requests

## No Tracking

- No analytics or telemetry
- No user identification or fingerprinting
- No cookies or third-party trackers
- No data sold or shared with third parties

## Data Retention

All data is stored locally in your browser. Uninstalling the extension removes all stored data. You can also clear all data from the Settings page at any time.

## Children's Privacy

The extension is not directed at children under 13 and does not knowingly collect data from children.

## Changes

Updates to this policy will be posted here with a revised date.

## Contact

For privacy-related questions or concerns:
- GitHub Issues: [github.com/niccolofant/eip7702-poc](https://github.com/niccolofant/eip7702-poc/issues)

---

*Testudo is open source software. You can review the code to verify these privacy practices.*
