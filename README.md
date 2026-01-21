<p align="center">
  <img src="docs/icon.png" alt="Testudo" width="128" height="128">
</p>

<h1 align="center">Testudo</h1>

<p align="center">
  EIP-7702 Security Auditor - Browser extension that detects malicious delegation contracts before users sign them.
</p>

## Problem

EIP-7702 enables EOA delegation to smart contracts. Since May 2025, $12M+ has been stolen from 15,000+ wallets through malicious delegations. 90%+ of delegation contracts are malicious.

## Solution

Testudo intercepts `eth_signTypedData_v4` requests, analyzes the delegate contract bytecode, and warns users before they sign dangerous authorizations.

## Features

- Real-time bytecode analysis
- Detection of auto-forwarders, delegatecall, selfdestruct, unlimited approvals
- Known malicious address database
- Risk scoring (Critical/High/Medium/Low)
- Browser extension with blocking warnings

## Installation

```bash
# Install dependencies
yarn install

# Build all packages
yarn build

# Run tests
yarn test
```

## Project Structure

```
packages/
  core/             # @testudo/core - Detection engine
    src/
      index.ts      # Public exports
      parser.ts     # Bytecode parser
      detectors.ts  # Threat detectors
      analyzer.ts   # Main orchestrator
      fetcher.ts    # Bytecode fetcher (viem)
      malicious-db.ts
    tests/          # 66 tests

  extension/        # @testudo/extension - Chrome extension
    src/
      injected.ts   # Intercepts ethereum.request
      content.ts    # Message bridge
      background.ts # Uses @testudo/core
      popup.ts      # Popup UI
    dist/           # Build output

docs/               # Documentation
```

## Usage

### Load Extension in Chrome

1. Build the extension: `yarn workspace @testudo/extension run build`
2. Open `chrome://extensions`
3. Enable "Developer mode"
4. Click "Load unpacked"
5. Select `packages/extension/dist/`

### Use Core Package

```typescript
import { analyzeContract } from '@testudo/core';

const result = await analyzeContract('0x...');
// { risk: 'CRITICAL', threats: ['hasAutoForwarder'], blocked: true }
```

## Documentation

- [Roadmap](docs/ROADMAP.md)
- [Architectural Decisions](docs/DECISIONS.md)
- [Project Status](docs/PROJECT_STATUS.md)

## License

MIT
