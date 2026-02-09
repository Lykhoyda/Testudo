# Testudo - EIP-7702 Security Auditor

## Instructions for Claude

**Before implementing any feature or making architectural decisions:**

1. Check `docs/adr/` for relevant Architecture Decision Records
2. Follow decisions documented in ADRs - they represent agreed-upon approaches
3. If a task requires a new architectural decision, note it and suggest creating a new ADR
4. Reference ADR numbers in commit messages when implementing related features (e.g., `[ADR-001]`)
5. When using Gemini MCP tool it's critical to use 'gemini-3-pro-preview' model for best results
**ADR Index**: @docs/adr/README.md

---

## Quick Context

**What**: Browser extension + API that detects malicious EIP-7702 delegation contracts before users sign them.

**Why**: $12M+ stolen from 15,000+ wallets since May 2025. 90%+ of delegations are malicious. Zero competition.

**Who**: Anton - Senior Web3 dev (built Dappeteer, MetaMask Snap, Multix, Sprinter SDK). Learning indie dev lifecycle.

**Goal**: 8-week MVP → EUR 5K MRR in 6 months via B2B API to wallet providers.

---

## Project Structure (Yarn Monorepo)

```
testudo/
├── package.json                  # Workspace root
├── LICENSE                       # MIT License
├── packages/
│   ├── core/                     # @testudo/core - Detection engine
│   │   ├── package.json
│   │   ├── rolldown.config.ts    # Bundler config
│   │   ├── src/
│   │   │   ├── index.ts          # Public exports
│   │   │   ├── parser.ts         # Bytecode parser
│   │   │   ├── detectors.ts      # 7 pattern detectors
│   │   │   ├── malicious-db.ts   # Known malicious addresses
│   │   │   ├── fetcher.ts        # Bytecode fetcher (viem)
│   │   │   ├── analyzer.ts       # Main analysis orchestrator
│   │   │   ├── opcode.ts         # Opcode constants
│   │   │   └── types.ts          # TypeScript interfaces
│   │   └── tests/                # 168 tests
│   │       ├── parser.test.ts
│   │       ├── detectors.test.ts
│   │       ├── malicious-db.test.ts
│   │       ├── integration.test.ts
│   │       └── fixtures/contracts.ts
│   │
│   └── extension/                # @testudo/extension - Chrome extension
│       ├── package.json
│       ├── manifest.json
│       ├── popup.html
│       ├── rolldown.config.ts    # Bundler config
│       ├── src/
│       │   ├── injected.ts       # Intercepts eth_signTypedData_v4
│       │   ├── content.ts        # Message bridge
│       │   ├── background.ts     # Imports from @testudo/core
│       │   └── popup.ts          # Popup UI
│       └── dist/                 # Build output
│
├── apps/
│   └── mock-dapp/                # Demo playground for testing extension
│
└── docs/
    ├── PROJECT_STATUS.md
    ├── ROADMAP.md
    ├── DECISIONS.md
    └── BUGS.md
```

> **Note**: The Threat Intelligence API (`@testudo/api`) lives in a separate private repository: [Lykhoyda/testudo-api](https://github.com/Lykhoyda/testudo-api)

---

## Current Status

### Completed

| Component | Package | Notes |
|-----------|---------|-------|
| Bytecode Fetcher | @testudo/core | viem getCode |
| Bytecode Parser | @testudo/core | PUSH1-PUSH32 handling |
| Database Lookup | @testudo/core | 4 malicious, 1 whitelisted |
| Auto-Forwarder Detector | @testudo/core | SELFBALANCE + CALL |
| DelegateCall Detector | @testudo/core | 0xF4 opcode |
| SelfDestruct Detector | @testudo/core | 0xFF as opcode |
| Unlimited Approval Detector | @testudo/core | PUSH32 all 0xFF |
| CREATE2 Detector | @testudo/core | 0xF5 opcode |
| CHAINID Detector | @testudo/core | 0x46 + branching + comparison |
| Metamorphic Pattern | @testudo/core | CREATE2 + SELFDESTRUCT |
| EIP-712 False Positive Prevention | @testudo/core | CHAINID → KECCAK256 = safe |
| User-Facing Warnings | @testudo/core | Threat-specific messages |
| Token Transfer Detector | @testudo/core | ERC20/721/1155 contextual analysis |
| Test Suite | @testudo/core | 135 tests passing |
| Extension | @testudo/extension | Manifest V3, rolldown build |

### Next Steps

1. Add Proxy Pattern Detection (EIP-1967)
2. Human-Readable Decoder (ANT-228)
3. Deployer nonce/age heuristic (ANT-225)

---

## Key Technical Decisions

### Parser: PUSH Opcode Handling

```
PUSH opcodes (0x60-0x7F) consume next N bytes as DATA:

0x60FF = PUSH1 0xFF → NOT SELFDESTRUCT (pushing data)
0x6000FF = PUSH1 0x00, SELFDESTRUCT → IS SELFDESTRUCT
```

### Monorepo Architecture

- `@testudo/core` - Shared detection engine (rolldown + tsc) — MIT licensed
- `@testudo/extension` - Imports core, bundles via rolldown — MIT licensed
- `@testudo/api` - Threat Intelligence API — **private repo** ([testudo-api](https://github.com/Lykhoyda/testudo-api))

### Risk Scoring

| Pattern | Risk | Blocked |
|---------|------|---------|
| Metamorphic (CREATE2 + SELFDESTRUCT) | CRITICAL | Yes |
| Auto-Forwarder | CRITICAL | Yes |
| Token transfer in fallback | CRITICAL | Yes |
| Token ops + hardcoded destination + no auth | CRITICAL | Yes |
| setApprovalForAll without auth | CRITICAL | Yes |
| 2+ threats | CRITICAL | Yes |
| SELFDESTRUCT alone | HIGH | Yes |
| DELEGATECALL alone | HIGH | Yes |
| CHAINID + branching + comparison | HIGH | Yes |
| CHAINID + branching | HIGH | Yes |
| Token ops without auth | HIGH | Yes |
| ecrecover without nonce (replay risk) | HIGH | Yes |
| CREATE2 alone | MEDIUM | No |
| CHAINID + comparison | MEDIUM | No |
| CHAINID alone | MEDIUM | No |
| Token ops with auth patterns | MEDIUM | No |
| EIP-712 pattern (CHAINID → KECCAK256) | SAFE | No |

### Known Addresses

```typescript
// MALICIOUS
'0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b' // ETH auto-forwarder

// SAFE
'0x63c0c19a282a1b52b07dd5a65b58948a07dae32b' // MetaMask delegator
```

---

## Commands Reference

```bash
# Install all dependencies
yarn install

# Build all packages
yarn build

# Run all tests
yarn test

# Build extension only
yarn workspace @testudo/extension run build

# Watch mode for extension
yarn dev

# Run core tests only
yarn workspace @testudo/core run test
```

---

## Project Documents

- `docs/ROADMAP.md` - Development phases
- `docs/DECISIONS.md` - Architectural decisions (legacy)
- `docs/PROJECT_STATUS.md` - Current status
- `docs/BUGS.md` - Bug tracking

---

## Architecture Decision Records

See @docs/adr/README.md for all ADRs.

### Key ADRs
- @docs/adr/ADR-001-bytecode-analysis-strategy.md
- @docs/adr/ADR-002-ai-positioning-strategy.md
- @docs/adr/ADR-003-adr-workflow.md
- @docs/adr/ADR-004-product-scope-evolution.md
- @docs/adr/ADR-005-threat-intelligence-backend.md
