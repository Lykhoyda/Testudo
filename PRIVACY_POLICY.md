# Privacy Policy for Testudo

**Last Updated: January 21, 2026**

> **Note:** Testudo is currently in active development and not yet available on the Chrome Web Store. This privacy policy applies to the upcoming public release.

## Overview

Testudo ("the Extension") is a browser extension that protects users from malicious EIP-7702 delegation contracts. We are committed to protecting your privacy and being transparent about our data practices.

## Data Collection

### What We Collect

**Locally Stored Data (on your device only):**
- Whitelisted contract addresses you explicitly trust
- Scan history (contract addresses and analysis results)
- Your custom RPC endpoint URL (if configured)
- Extension settings and preferences

### What We Do NOT Collect or Transmit

- Personal information (name, email, etc.)
- Transaction data or balances
- Browsing history
- Analytics or telemetry data

Note: Contract addresses you whitelist are stored locally on your device only.

## How Data Is Used

All data processing and analysis occurs **locally on your device**:

1. **Contract Analysis**: When you interact with an EIP-7702 delegation request, the Extension:
   - Fetches the contract bytecode from a public Ethereum RPC endpoint (network request)
   - Analyzes the bytecode entirely on your device (local processing)
   - No analysis results or personal data are sent anywhere

2. **Whitelist**: Addresses you trust are stored locally to skip future warnings.

3. **Scan History**: Recent scans are stored locally so you can review past analyses.

## Data Storage

- All data is stored in your browser's local storage (`chrome.storage.local`)
- Data never leaves your device
- Data is not synced across devices
- You can clear all data at any time via the Extension settings

## Third-Party Services

The Extension connects to public Ethereum RPC endpoints to fetch contract bytecode:

- Default: `eth.llamarpc.com` (LlamaNodes public RPC)
- You can configure a custom RPC endpoint in settings

These RPC requests contain only the contract address being analyzed. No personal data is transmitted.

## Data Sharing

We do **not** share, sell, or transmit any data to third parties. All analysis is performed locally.

## Your Rights

You have full control over your data:

- **View**: Access all stored data in Extension settings
- **Export**: Export your whitelist as JSON
- **Delete**: Clear all data via the "Clear All Data" button in settings
- **Modify**: Add or remove whitelist entries at any time

## Security

- The Extension operates with minimal required permissions
- No Testudo-owned servers or databases - we don't collect your data
- Only connects to public Ethereum RPC endpoints to fetch contract code
- Open source code available for audit
- All analysis and sensitive operations happen locally on your device

## Children's Privacy

The Extension is not directed at children under 13 and does not knowingly collect data from children.

## Changes to This Policy

We may update this Privacy Policy from time to time. Changes will be reflected in the "Last Updated" date above.

## Contact

For privacy-related questions or concerns:

- GitHub Issues: [github.com/Lykhoyda/testudo](https://github.com/Lykhoyda/testudo)
- Email: lykhoyda@gmail.com

## Permissions Explained

The Extension requests the following permissions:

| Permission | Purpose |
|------------|---------|
| `storage` | Store whitelist, settings, and scan history locally on your device |
| `activeTab` | Access the current tab to display analysis results in the popup UI |
| `host_permissions` (all URLs) | Required to fetch contract bytecode from Ethereum RPC endpoints for security analysis. The extension makes requests only to RPC nodes (default: eth.llamarpc.com) to retrieve smart contract code. |
| `content_scripts` (all URLs) | Inject the security script that intercepts delegation signature requests before they reach your wallet. This runs on all sites because malicious dApps can be hosted anywhere. |

### Why "All URLs"?

Testudo requires broad permissions because:
1. **Malicious dApps can be hosted on any domain** - We cannot predict where threats will appear
2. **RPC endpoints vary** - Users may configure custom RPC URLs
3. **Protection must be universal** - Limiting to specific sites would leave users vulnerable

**What we do NOT do with these permissions:**
- Read or modify your browsing data
- Track your browsing history
- Access page content unrelated to EIP-7702 delegations
- Send any data to our servers (we have none)

---

*Testudo is open source software. You can review our code to verify these privacy practices.*
