# Testudo — Transaction Security for the Ethereum Ecosystem

## Instructions for Claude

**Before implementing any feature or making architectural decisions:**

1. Check `docs/adr/` for relevant Architecture Decision Records
2. Follow decisions documented in ADRs — they represent agreed-upon approaches
3. If a task requires a new architectural decision, note it and suggest creating a new ADR
4. Reference ADR numbers in commit messages when implementing related features (e.g., `[ADR-001]`)
5. When using Gemini MCP tool it's critical to ALWAYS use 'gemini-3-pro-preview' model for best results
6. Check nested `CLAUDE.md` files in `packages/core/` and `packages/extension/` for package-specific context

**ADR Index**: @docs/adr/README.md

---

## Quick Context

**What**: Browser extension + API that acts as an antivirus for Ethereum transactions — analyzing contracts and signatures before users sign. Detects malicious EIP-7702 delegations, token approvals, permits, blind signatures, phishing, and more across Ethereum L1/L2/L3.

**Why**: $12M+ stolen from 15,000+ wallets since May 2025. Users sign transactions they don't understand — Testudo makes every signature human-readable and flags threats before damage occurs.

**Who**: Anton — Senior Web3 dev (built Dappeteer, MetaMask Snap, Multix, Sprinter SDK).

**Goal**: 8-week MVP → EUR 5K MRR in 6 months via B2B API to wallet providers.

**Scope**: Ethereum ecosystem only — L1 (mainnet), L2s (Arbitrum, Optimism, Base, zkSync), and L3s. No non-Ethereum chains (BSC, Solana, etc.).

**Positioning**: "Human-Readable Signature Layer" — deterministic detection with explainable results (see ADR-002, ADR-004).

---

## Project Structure (Yarn Monorepo)

```
testudo/
├── package.json                  # Workspace root (Yarn workspaces)
├── LICENSE                       # MIT License
├── CLAUDE.md                     # This file — project-wide context
├── packages/
│   ├── core/                     # @testudo/core — Detection engine (190 tests)
│   │   ├── CLAUDE.md             # Package-specific context
│   │   ├── rolldown.config.ts
│   │   ├── src/
│   │   │   ├── index.ts          # Public exports
│   │   │   ├── analyzer.ts       # Main orchestrator (291 lines)
│   │   │   ├── detectors.ts      # 14 detection functions (378 lines)
│   │   │   ├── deployer-risk.ts  # Deployer nonce/age scoring (67 lines)
│   │   │   ├── parser.ts         # Bytecode parser
│   │   │   ├── fetcher.ts        # Bytecode fetcher (viem)
│   │   │   ├── malicious-db.ts   # Known malicious/safe addresses
│   │   │   ├── opcode.ts         # EVM opcode constants
│   │   │   └── types.ts          # TypeScript interfaces (117 lines)
│   │   └── tests/                # 190 tests (5 test files)
│   │
│   ├── extension/                # @testudo/extension — Chrome extension (Preact + Signals)
│   │   ├── CLAUDE.md             # Package-specific context
│   │   ├── manifest.json         # MV3 manifest
│   │   ├── rolldown.config.ts    # Bundler config (Preact JSX, 5 entry points)
│   │   ├── src/
│   │   │   ├── injected.tsx      # Page-context orchestrator (566 lines)
│   │   │   ├── content.ts        # Message bridge + heartbeat (256 lines)
│   │   │   ├── background.ts     # Service worker + analysis (656 lines)
│   │   │   ├── popup.tsx         # Popup entry point
│   │   │   ├── options.tsx       # Options entry point
│   │   │   ├── storage.ts        # Chrome storage utilities
│   │   │   ├── safe-filter.ts    # CDN safe address filter
│   │   │   ├── api-client.ts     # API client (timeout/retry)
│   │   │   ├── env.d.ts          # Build-time env types
│   │   │   ├── hooks/            # VM stores (warningVM, popupVM, optionsVM)
│   │   │   ├── components/       # Preact components (warning/, popup/, options/, shared/)
│   │   │   ├── decoder/          # Human-readable intent (format, intent-builder, token-resolver)
│   │   │   ├── parsers/          # Input parsers (phishing, transaction, blind-signature, typed-data)
│   │   │   ├── services/         # IPC bridge + deployer lookup
│   │   │   └── utils/            # Types, constants, formatters, threat-data
│   │   └── dist/                 # Build output
│   │
│   └── e2e/                      # @testudo/e2e — Playwright E2E tests (43 tests)
│       └── tests/
│           └── extension.spec.ts
│
├── apps/
│   └── mock-dapp/                # Demo dApp for testing (Vite + React)
│
└── docs/
    ├── adr/                      # Architecture Decision Records (13 ADRs)
    ├── ROADMAP.md
    ├── DECISIONS.md
    ├── PROJECT_STATUS.md
    └── BUGS.md
```

> **Note**: The Threat Intelligence API (`@testudo/api`) lives in a separate private repository: [Lykhoyda/testudo-api](https://github.com/Lykhoyda/testudo-api)

---

## Current Status

### Detection Capabilities

| Capability | Package | Method |
|-----------|---------|--------|
| EIP-7702 delegation analysis | core + extension | Bytecode capability extraction |
| Token approvals (approve, increaseAllowance) | extension | Calldata decoding |
| NFT setApprovalForAll | extension | Calldata decoding + marketplace list |
| Permit/Permit2 signatures | extension | Typed data primaryType detection |
| Blind signatures (personal_sign) | extension | Phishing pattern scoring |
| eth_sign hard block | extension | Always CRITICAL, typed confirmation |
| Typed data address scanning | extension | Recursive address extraction + batch check |
| eth_sendTransaction malicious recipient | extension | Address-only check pipeline |
| Deployer nonce/age heuristic | core + extension | Blockscout API + viem RPC |
| Human-readable intent decoder | extension | Token metadata + intent builder |
| MV3 heartbeat / loading UI | extension | SW keep-alive + optimistic modal |

### Infrastructure

| Component | Status | Notes |
|-----------|--------|-------|
| 3-layer defense | Complete | Safe Filter → Local DB → API → Bytecode |
| Build system | Complete | Rolldown, ~85ms build |
| Core tests | 190 passing | 5 test files |
| Extension tests | 86 passing | Decoder + deployer-lookup (4 test files) |
| E2E tests | 43 passing | Playwright + Chrome extension |
| Chrome Web Store | Submitted | ANT-240, fonts bundled, permissions pinned |

### Bundle Sizes

| Entry | Size |
|-------|------|
| injected.js | 72 KB |
| content.js | 4.4 KB |
| background.js | 288 KB |
| popup.js | 24 KB |
| options.js | 33 KB |

### Next Steps

1. Human-Readable Decoder polish (ANT-228 follow-ups)
2. Proxy pattern detection (EIP-1967)
3. Shadow DOM isolation for warning modals

---

## Key Technical Decisions

### Parser: PUSH Opcode Handling

```
PUSH opcodes (0x60-0x7F) consume next N bytes as DATA:
0x60FF = PUSH1 0xFF → NOT SELFDESTRUCT (pushing data)
0x6000FF = PUSH1 0x00, SELFDESTRUCT → IS SELFDESTRUCT
```

### Monorepo Architecture

- `@testudo/core` — Detection engine (rolldown + tsc), MIT licensed
- `@testudo/extension` — Chrome extension (Preact + Signals, rolldown), MIT licensed
- `@testudo/api` — Threat Intelligence API, **private repo** ([testudo-api](https://github.com/Lykhoyda/testudo-api))

### Risk Scoring

| Pattern | Risk | Blocked |
|---------|------|---------|
| Metamorphic (CREATE2 + SELFDESTRUCT) | CRITICAL | Yes |
| Auto-Forwarder | CRITICAL | Yes |
| Token transfer in fallback | CRITICAL | Yes |
| Token ops + hardcoded destination + no auth | CRITICAL | Yes |
| setApprovalForAll without auth | CRITICAL | Yes |
| 2+ threats (at least 1 HIGH) | CRITICAL | Yes |
| Deployer nonce<5 + age<24h | CRITICAL | Yes |
| SELFDESTRUCT alone | HIGH | Yes |
| DELEGATECALL alone | HIGH | Yes |
| CHAINID + branching + comparison | HIGH | Yes |
| CHAINID + branching (no comparison) | HIGH | Yes |
| Token ops without auth | HIGH | Yes |
| ecrecover without nonce (replay risk) | HIGH | Yes |
| Deployer nonce<5 | HIGH | Yes |
| 2+ MEDIUM threats | HIGH | Yes |
| CREATE2 alone | MEDIUM | No |
| CHAINID + comparison | MEDIUM | No |
| CHAINID alone | MEDIUM | No |
| Token ops with auth patterns | MEDIUM | No |
| Deployer nonce 5-50 + age<24h | MEDIUM | No |
| EIP-712 pattern (CHAINID → KECCAK256) | SAFE | No |

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

# Run E2E tests (requires mock-dapp preview + API running separately)
yarn workspace @testudo/e2e run test

# Lint
yarn biome check .
```

---

## Project Documents

- `docs/ROADMAP.md` — Development phases and completed features
- `docs/DECISIONS.md` — Architectural decisions log
- `docs/PROJECT_STATUS.md` — Current status summary
- `docs/BUGS.md` — Bug tracking and improvement suggestions

---

## Architecture Decision Records

See @docs/adr/README.md for all ADRs.

### Key ADRs
- @docs/adr/ADR-001-bytecode-analysis-strategy.md — Bytecode capability extraction approach
- @docs/adr/ADR-002-ai-positioning-strategy.md — "AI-powered research, deterministic protection"
- @docs/adr/ADR-004-product-scope-evolution.md — From EIP-7702 tool to capability analyzer
- @docs/adr/ADR-005-threat-intelligence-backend.md — Hono + PostgreSQL + Railway
- @docs/adr/ADR-006-extension-integration-architecture.md — 3-layer defense architecture
- @docs/adr/ADR-010-preact-signals-mvvm-architecture.md — Extension UI architecture (Preact + Signals MVVM)
