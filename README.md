# Testudo

EIP-7702 Security Auditor - Browser extension that detects malicious delegation contracts before users sign them.

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

# Run tests
yarn test

# Build extension
cd extension && npm install && npm run build
```

## Project Structure

```
src/
  analyzer/
    index.ts        # Main orchestrator
    fetcher.ts      # Bytecode fetcher (viem)
    parser.ts       # Bytecode parser
    detectors.ts    # Threat detectors
    malicious-db.ts # Known addresses
  types.ts          # TypeScript interfaces

extension/          # Chrome extension (Manifest V3)

tests/              # Test suite (56 tests)

docs/               # Documentation
  ROADMAP.md        # Development roadmap
  BUGS.md           # Bug tracking
  DECISIONS.md      # Architectural decisions
  PROJECT_STATUS.md # Detailed progress
```

## Documentation

- [Roadmap](docs/ROADMAP.md)
- [Architectural Decisions](docs/DECISIONS.md)
- [Project Status](docs/PROJECT_STATUS.md)

## License

MIT
