<p align="center">
  <img src="packages/extension/store-assets/icon.png" alt="Testudo" width="128" height="128">
</p>

<h1 align="center">Testudo</h1>

<p align="center">
  Transaction security for the Ethereum ecosystem — a browser extension that analyzes contracts and signatures before you sign, detecting threats across EIP-7702 delegations, token approvals, permits, blind signatures, and more.
</p>

<p align="center">
  <a href="https://chromewebstore.google.com/detail/testudo/gpidnceilfbhhcpheagjpkdioohmkpmb">
    <img src="https://img.shields.io/badge/Chrome_Web_Store-Install-4285F4?logo=googlechrome&logoColor=white" alt="Install from Chrome Web Store">
  </a>
  &nbsp;
  <a href="https://testudomock-dapp-production.up.railway.app">
    <img src="https://img.shields.io/badge/Playground-Try_Demo-00C853" alt="Try the Demo Playground">
  </a>
</p>

## Problem

Users sign transactions they don't understand. Since May 2025, $12M+ has been stolen from 15,000+ wallets through malicious EIP-7702 delegations alone — and that's just one attack vector. Token approvals, permit signatures, and blind signing expose users to unlimited drains with a single click.

## Solution

Testudo acts as an antivirus for every Ethereum transaction. It intercepts signature requests, analyzes the target contract's bytecode and intent, and presents human-readable warnings before users sign anything dangerous.

## Detection Capabilities

| Capability | Method |
|-----------|--------|
| EIP-7702 delegation analysis | Bytecode capability extraction (14 detectors) |
| Token approvals (`approve`, `increaseAllowance`) | Calldata decoding + address check |
| NFT `setApprovalForAll` | Calldata decoding + marketplace allowlist |
| Permit / Permit2 signatures | Typed data primaryType detection |
| Blind signatures (`personal_sign`) | Phishing pattern scoring |
| `eth_sign` hard block | Always CRITICAL, typed confirmation required |
| Typed data address scanning | Recursive address extraction + batch check |
| Malicious transaction recipients | Address-only check pipeline |
| Deployer reputation | Nonce/age heuristic via Blockscout + RPC |
| Human-readable intent | Token metadata resolution + intent builder |

## Architecture

**3-layer defense** — every unknown address passes through:

1. **Safe Filter** (local, instant) — known-good addresses skip API
2. **Threat Intelligence API** (800ms timeout) — 15K+ malicious addresses + GoPlus real-time fallback
3. **Local Bytecode Analysis** (parallel) — 14 deterministic detectors, no ML

All results are **explainable**: "This contract HAS capability X because of opcode Y at offset Z."

## Installation

### From Chrome Web Store

Install directly: **[Testudo on Chrome Web Store](https://chromewebstore.google.com/detail/testudo/gpidnceilfbhhcpheagjpkdioohmkpmb)**

### From Source

```bash
# Install dependencies
yarn install

# Build all packages
yarn build

# Run tests
yarn test
```

#### Load Extension in Chrome

1. Build the extension: `yarn workspace @testudo/extension run build`
2. Open `chrome://extensions`
3. Enable "Developer mode"
4. Click "Load unpacked"
5. Select `packages/extension/dist/`

## Project Structure

```
packages/
  core/             # @testudo/core — Detection engine (190 tests)
  extension/        # @testudo/extension — Chrome extension (Preact + Signals)
  e2e/              # End-to-end tests (Playwright, 43 tests)

apps/
  mock-dapp/        # Demo playground for testing
```

> **Note**: The Threat Intelligence API lives in a [separate private repository](https://github.com/Lykhoyda/testudo-api).

### Use Core Package

```typescript
import { analyzeContract } from '@testudo/core';

const result = await analyzeContract('0x...');
// { risk: 'CRITICAL', threats: ['hasAutoForwarder'], blocked: true }
```

## Demo Playground

Try Testudo in action: **[testudomock-dapp-production.up.railway.app](https://testudomock-dapp-production.up.railway.app)**

The playground simulates various transaction types:
- **EIP-7702 delegations** — safe (MetaMask delegator) and malicious (known drainer)
- **Token approvals** — unlimited amounts, malicious spenders
- **NFT setApprovalForAll** — unknown operators, marketplace allowlist
- **Permit/Permit2 signatures** — gasless approval attacks
- **Blind signatures** — phishing pattern detection
- **eth_sign** — hard block with typed confirmation

## License

MIT
