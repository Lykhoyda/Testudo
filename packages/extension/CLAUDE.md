# @testudo/extension — Chrome Extension

Manifest V3 browser extension. Preact + Signals UI, rolldown bundler. MIT licensed.

## Architecture

### Entry Points (5 bundles)

| Entry | Context | Role | Size |
|-------|---------|------|------|
| `injected.tsx` | Page | Intercepts `window.ethereum.request`, orchestrates all detection flows | 72 KB |
| `content.ts` | Content script | Message bridge between page ↔ background, font injection, heartbeat | 4.6 KB |
| `background.ts` | Service worker | Analysis engine, API client, storage, token resolution | 288 KB |
| `popup.tsx` | Extension popup | Stats, recent scans | 24 KB |
| `options.tsx` | Options page | Settings, whitelist, history | 33 KB |

### Detection Flow (injected.tsx)

```
window.ethereum.request intercepted
  → Permits (eth_signTypedData_v4 + Permit primaryType)
  → EIP-7702 delegations (eth_signTypedData_v4 + Authorization type)
  → Generic typed data scan (address extraction + batch check)
  → Token approvals (eth_sendTransaction + approve/increaseAllowance calldata)
  → NFT setApprovalForAll (eth_sendTransaction + setApprovalForAll calldata)
  → Malicious recipient (eth_sendTransaction + address check)
  → Blind signatures (personal_sign)
  → eth_sign hard block (always CRITICAL)
  → Fall through to wallet
```

### Message Bridge (content.ts → background.ts)

**Transport**: CustomEvent + nonce channel (ADR-011). Content script generates `crypto.randomUUID()` nonce, passes via `data-testudo-nonce` attribute. Injected script reads nonce and creates channel with nonce-prefixed event names. Prevents response forgery by hostile dApps.

**Constants**: `src/utils/message-types.ts` — shared `MessageTypes` object (use instead of raw strings).

| Message Type | Direction | Purpose |
|-------------|-----------|---------|
| `TESTUDO_ANALYZE_REQUEST` | page → bg | Full EIP-7702 bytecode analysis |
| `TESTUDO_CHECK_ADDRESS` | page → bg | Address-only check (Safe Filter → Local DB → API) |
| `TESTUDO_RESOLVE_TOKEN` | page → bg | ERC20 metadata via RPC multicall |
| `TESTUDO_GET_SETTINGS` | page → bg | Read extension settings |
| `TESTUDO_RECORD_BLOCKED` | page → bg | Record blocked transaction |
| `HEARTBEAT` | content → bg | Keep service worker alive |

## Directory Structure

```
src/
├── injected.tsx          # Page-context orchestrator
├── content.ts            # Message bridge + heartbeat
├── background.ts         # Service worker
├── popup.tsx             # Popup entry point
├── options.tsx           # Options entry point
├── storage.ts            # Chrome storage utilities
├── safe-filter.ts        # CDN safe address set
├── api-client.ts         # API client (800ms timeout, 1 retry)
├── env.d.ts              # Build-time env types
│
├── hooks/                # VM stores (singleton signals, NOT React hooks)
│   ├── warningVM.ts      # Warning modal state + Promise lifecycle
│   ├── popupVM.ts        # Popup stats/scans state
│   └── optionsVM.ts      # Options tabs/settings state
│
├── components/
│   ├── warning/          # Warning modal (11 components + CSS)
│   │   ├── WarningModal.tsx    # Root: loading → full modal → null
│   │   ├── LoadingState.tsx    # Optimistic loading UI
│   │   ├── ModalHeader.tsx     # Title + subtitle + intent headline
│   │   ├── AlertBox.tsx        # Risk severity alert
│   │   ├── ContextDetails.tsx  # Context-specific info + intent display
│   │   ├── ThreatList.tsx      # Threat items with icons
│   │   ├── AddressBox.tsx      # Address display + copy
│   │   ├── ModalButtons.tsx    # Cancel/Proceed/Trust actions
│   │   ├── EthSignConfirm.tsx  # Typed confirmation input
│   │   ├── InfoToast.tsx       # Non-blocking info notification
│   │   ├── UnknownToast.tsx    # Unknown address notification
│   │   └── warning-styles.ts   # CSS string (injected into page)
│   ├── popup/            # PopupApp, StatsGrid, RecentActivity
│   ├── options/          # OptionsApp, TabNav, GeneralTab, WhitelistTab, HistoryTab, AdvancedTab, Toast
│   └── shared/           # MaterialIcon
│
├── decoder/              # Human-readable intent system
│   ├── index.ts          # buildIntent() dispatcher
│   ├── format.ts         # formatTokenAmount, formatDeadline, getChainName
│   ├── intent-builder.ts # 8 context-specific builders
│   └── token-resolver.ts # Well-known tokens (14) + RPC fallback
│
├── parsers/              # Input parsing (pure functions)
│   ├── phishing.ts       # Phishing pattern scoring
│   ├── transaction.ts    # Approval/NFT calldata parsing
│   ├── blind-signature.ts # personal_sign/eth_sign parsing
│   └── typed-data.ts     # EIP-7702, permit, address extraction
│
├── services/             # I/O bridges
│   ├── channel.ts        # CustomEvent + nonce channel (ADR-011)
│   ├── messaging.ts      # IPC: sendTestudoRequest, requestAddressCheck, etc.
│   └── deployer-lookup.ts # Blockscout API + viem RPC
│
└── utils/
    ├── types.ts          # All extension-specific TypeScript interfaces
    ├── constants.ts      # Selectors, known marketplaces, max values
    ├── formatters.ts     # Shared formatting (truncateAddress, etc.)
    ├── message-types.ts  # Shared MessageTypes constants
    └── threat-data.ts    # THREAT_REGISTRY: {icon, shortDesc, format} per WarningType
```

## UI Framework

**Preact + @preact/signals** (not React).

### Critical Build Config

Rolldown `transform.jsx.mode: 'automatic'` does NOT read tsconfig `jsxImportSource`. You MUST explicitly set `importSource: 'preact'`:

```typescript
transform: { jsx: { mode: 'automatic', importSource: 'preact' } }
```

Without this, JSX defaults to `react/jsx-runtime` and produces `$$typeof` elements that Preact silently ignores (empty output).

### Signals Integration

Entry points (`injected.tsx`, `popup.tsx`, `options.tsx`) must include bare import:
```typescript
import '@preact/signals';
```
This side-effect installs Preact integration hooks. Without it, signal changes don't trigger re-renders.

### VM Pattern

Files in `hooks/` are **singleton signal stores**, not React hooks. Named `warningVM.ts`, `popupVM.ts`, `optionsVM.ts` (NOT `use*` prefix).

- `warningVM.ts` — Core: `state` signal with `WarningState`, `show()`, `showLoading()`, `updateAnalysis()`, `dismissLoading()`, `cancel()`, `proceed()`. Promise lifecycle via signal-stored resolver.
- `popupVM.ts` — Stats, recent scans
- `optionsVM.ts` — Settings, whitelist, history, active tab

## Warning Modal Promise Lifecycle

```
showLoading(opts)  → returns Promise<boolean>
  → updateAnalysis(analysis, intent?)  → transitions loading → full modal
  OR
  → dismissLoading()  → resolves true (fail-open, no user decision needed)

show(opts)  → returns Promise<boolean>
  → cancel()   → resolves false (records TESTUDO_RECORD_BLOCKED if not loading)
  → proceed()  → resolves true

Previous pending Promise is always resolved(false) before overwriting state.
```

## Warning Contexts

| Context | Trigger | Key Info |
|---------|---------|----------|
| `delegation` | EIP-7702 typed data | Full bytecode analysis + deployer risk |
| `transaction` | eth_sendTransaction to malicious address | Address check only |
| `permit` | Permit/Permit2 typed data | Token, amount, deadline, spender |
| `approval` | approve()/increaseAllowance() calldata | Token, amount, spender |
| `nft-approval` | setApprovalForAll() calldata | Collection, operator |
| `blind-signature` | personal_sign | Message preview, phishing score |
| `typed-data-scan` | Malicious address in typed data fields | Extracted addresses |
| `eth-sign-danger` | eth_sign | Always CRITICAL, typed confirmation required |

## Build

```bash
yarn workspace @testudo/extension run build   # ~85ms
```

- Build-time env: `TESTUDO_API_URL` (default: Railway production URL)
- CSS injected as string via `warning-styles.ts` (page context, no chrome.runtime access)
- Fonts bundled locally in `fonts/` (no external CDN)

## Unit Tests (100 total)

Located in `packages/extension/tests/`:

| File | Count | Tests |
|------|-------|-------|
| decoder/format.test.ts | 33 | Token amount formatting, deadline, chain names |
| decoder/intent-builder.test.ts | 32 | All 8 context-specific intent builders |
| decoder/token-resolver.test.ts | 16 | Well-known lookup, RPC fallback, cache |
| services/deployer-lookup.test.ts | 8 | Blockscout API, viem RPC, error handling |
| services/channel.test.ts | 11 | Channel isolation, nonce lifecycle, empty guard |

```bash
yarn workspace @testudo/extension run test
```

## E2E Tests (43 tests)

Located in `packages/e2e/tests/extension.spec.ts`. Requires:
- Mock-dapp preview server (port 4173)
- API running separately from `testudo-api` repo (or tests that need API skip gracefully)

Key selectors preserved for E2E: `#testudo-*`, `.testudo-*`

## Important Patterns

- **Fail-open**: All analysis errors resolve the Promise and pass through to wallet. Never break dApps.
- **ensureModalRoot()**: Checks `modalRoot?.isConnected` for SPA resilience (re-creates if detached from DOM).
- **No dangerouslySetInnerHTML**: Preact JSX auto-escapes text nodes. Use `ComponentChildren` for inline elements.
- **Address checks**: `requestAddressCheck()` → content bridge → background `performAddressOnlyCheck()` (Safe Filter → Local DB → API).
- **Token resolution**: Well-known tokens (14, instant) → in-memory cache (500 max) → RPC multicall via background script (2s timeout).
- **Deployer lookup**: Blockscout API (free, no key, 3s timeout) + viem RPC, runs in parallel with other analysis layers.
- **MV3 heartbeat**: Content script pings SW on page load. 20s interval on known dApp domains keeps SW alive.
