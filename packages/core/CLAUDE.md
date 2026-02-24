# @testudo/core — Detection Engine

Pure, deterministic bytecode analysis library. No I/O in production detection path. MIT licensed.

## Architecture

```
src/
├── index.ts          # Public exports (all re-exports)
├── analyzer.ts       # Orchestrator: fetchBytecode → parse → detect → score → warnings
├── detectors.ts      # 23 detection functions (runAllDetectors)
├── deployer-risk.ts  # Deployer nonce/age scoring (pure functions, no I/O)
├── parser.ts         # Bytecode → Instruction[] (handles PUSH1-PUSH32)
├── fetcher.ts        # viem getCode wrapper
├── malicious-db.ts   # Known malicious/safe address maps
├── opcode.ts         # EVM opcode constants
└── types.ts          # All TypeScript interfaces
```

## Key Types

- `AnalysisResult` — Main output: address, risk, threats[], warnings[], blocked, deployerRisk
- `Warning` — { type: WarningType, severity, title, description, technical? }
- `WarningType` — 33 values (AUTO_FORWARDER, DELEGATE_CALL, ..., MINIMAL_PROXY, DIAMOND_PROXY)
- `DetectionResults` — Raw detector output (booleans + TokenTransferAnalysis)
- `DeployerInfo` / `DeployerRiskAssessment` — Deployer reputation data

## Detection Pipeline

```
analyzeContract(address, options?)
  → fetchBytecode(address)        # viem getCode
  → parseBytecode(hex)            # Instruction[] with correct PUSH handling
  → runAllDetectors(instructions) # 23 detectors → DetectionResults
  → generateWarnings(results)     # DetectionResults → Warning[]
  → deriveRiskFromWarnings(warnings) # Warning[] → risk level + blocked flag
```

## Detectors (detectors.ts — 30 functions)

`runAllDetectors()` orchestrates all detectors and returns `DetectionResults`.

| Risk Category | Detection Functions | Looks For | Risk |
|---------------|-------------------|-----------|------|
| Auto-Forwarder | detectAutoForwarder | SELFBALANCE → CALL within 15 instructions | CRITICAL |
| DelegateCall | detectDelegateCall | DELEGATECALL opcode | HIGH (MEDIUM if proxy/wallet) |
| Callcode | detectCallcode | CALLCODE opcode (deprecated DELEGATECALL) | HIGH (MEDIUM if proxy/wallet) |
| SelfDestruct | detectSelfDestruct | SELFDESTRUCT as opcode (not PUSH data) | HIGH |
| CREATE2 | detectCreate2 | CREATE2 opcode | MEDIUM |
| Metamorphic | CREATE2 + SELFDESTRUCT combined | Both present | CRITICAL |
| CHAINID | detectChainId | CHAINID + branching/comparison patterns | MEDIUM-HIGH |
| Token Transfer | detectTokenSelectors, detectEcrecover, detectMsgSenderCheck, detectNonceTracking, detectFallbackLocation, detectHardcodedDestination, analyzeTokenTransfers | ERC20/721/1155 selectors + auth patterns | Context-dependent |
| Unlimited Approval | detectUnlimitedApproval | PUSH32 all 0xFF | MEDIUM |
| Proxy Pattern | detectProxyPattern | EIP-1967 storage slots (impl/admin/beacon) | MEDIUM |
| tx.origin Phishing | detectTxOrigin | ORIGIN + EQ comparison pattern | HIGH |
| Balance Drain | detectBalanceDrain | BALANCE → comparison → CALL/SELFDESTRUCT | HIGH |
| EXTCODECOPY | detectExtcodecopy | EXTCODECOPY opcode (code injection with CREATE2) | INFO (MEDIUM with CREATE2) |
| EIP-7702 Delegation | detectEip7702Delegation | 0xEF0100 prefix + 20-byte address | INFO |
| Timestamp Dependence | detectTimestampDependence | TIMESTAMP + comparison + JUMPI | MEDIUM |
| Multicall/Batch | detectMulticall | multicall/aggregate/tryAggregate selectors | MEDIUM |
| EXTCODESIZE Guard | detectExtcodesizeGuard | EXTCODESIZE + ISZERO/EQ/GT | INFO |
| ERC-4337 Account Abstraction | detectErc4337Pattern | EntryPoint addresses + handleOps/validateUserOp | INFO (mitigates DELEGATECALL) |
| COINBASE Dependence | detectCoinbaseDependence | COINBASE + comparison + JUMPI | MEDIUM |
| EIP-1167 Minimal Proxy | detectMinimalProxy | Canonical 45-byte bytecode pattern | INFO (mitigates DELEGATECALL) |
| Reentrancy Pattern | detectReentrancyRisk | CALL/DELEGATECALL/CALLCODE → SSTORE (STATICCALL excluded) | HIGH |
| Gas Manipulation | detectGasManipulation | GAS + comparison + JUMPI branching | MEDIUM |
| EXTCODEHASH | detectExtcodehash | EXTCODEHASH opcode (EIP-7702 code hash interaction) | INFO |
| Diamond Proxy (EIP-2535) | detectDiamondProxy | diamondCut/facets/facetAddress selectors | MEDIUM (mitigates DELEGATECALL) |

## Deployer Risk (deployer-risk.ts)

Pure scoring — no I/O. Extension provides `DeployerInfo`, core returns `DeployerRiskAssessment`.

| Nonce | Contract Age | Risk |
|-------|-------------|------|
| < 5 | < 24h | CRITICAL |
| < 5 | >= 24h | HIGH |
| 5-50 | < 24h | MEDIUM |
| 50+ | any | LOW |

## Known Addresses (malicious-db.ts)

- `KNOWN_MALICIOUS` — Map of confirmed drainer contracts
- `KNOWN_SAFE` — Map of verified safe contracts (MetaMask delegator, etc.)
- `checkKnownMalicious(address)` — Returns AnalysisResult or null
- `isKnownSafe(address)` — Boolean check

## Build

```bash
yarn workspace @testudo/core run build    # rolldown + tsc
yarn workspace @testudo/core run test     # vitest, 375 tests
```

- viem is marked `external` in rolldown config (prevents double-bundling with extension)
- Output: ESM, ~25KB

## Tests (373 total)

| File | Count | Tests |
|------|-------|-------|
| parser.test.ts | 18 | PUSH opcode handling, edge cases, PUSH0, truncation |
| detectors.test.ts | 212 | All detectors with real bytecode fixtures |
| malicious-db.test.ts | 8 | Known address lookups |
| integration.test.ts | 115 | Full pipeline, warnings, risk scoring, drainer patterns, combination threats, deployer interactions |
| deployer-risk.test.ts | 22 | Risk matrix scoring |

## Important Patterns

- **PUSH data vs opcodes**: `0x60FF` is PUSH1 pushing `0xFF` (data), NOT SELFDESTRUCT. Parser skips N bytes after PUSH opcodes.
- **EIP-712 false positive**: CHAINID followed by KECCAK256 = EIP-712 signature hashing, not cross-chain attack. Detector marks as SAFE.
- **Risk escalation**: 2+ MEDIUM warnings → HIGH (not CRITICAL, avoids false positives on smart wallets).
- **Fail-open**: Analysis errors return UNKNOWN risk with `blocked: false`.
- **Bytecode-level detectors**: `detectMinimalProxy` and `detectEip7702Delegation` work on raw hex strings, not parsed instructions.
- **Auto-forwarder proximity**: SELFBALANCE must be within 15 instructions before CALL. Prevents flagging contracts that use both opcodes in separate code paths.
- **DELEGATECALL mitigation**: When a proxy/wallet pattern (EIP-1967, EIP-1167, EIP-2535, ERC-4337) is co-detected, DELEGATECALL severity drops from HIGH to MEDIUM. Pure DELEGATECALL without proxy remains HIGH.
- **SELFDESTRUCT post-Dencun**: After EIP-6780, SELFDESTRUCT only sends ETH balance; it does NOT destroy contract code (except same-tx creation). Warning text updated accordingly.
- **Auth window**: `detectMsgSenderCheck` uses 10-instruction window (LOOK_AHEAD.branching) to accommodate Solidity compiler stack manipulation between CALLER and EQ.
- **BALANCE vs SELFBALANCE**: BALANCE (0x31) checks another address's balance; SELFBALANCE (0x47) checks the contract's own. `detectBalanceDrain` looks for BALANCE → comparison → CALL/SELFDESTRUCT (drain indicator). `detectAutoForwarder` looks for SELFBALANCE → CALL (auto-forward).
- **EXTCODECOPY escalation**: EXTCODECOPY alone is INFO (legitimate in factories). EXTCODECOPY + CREATE2 (without SELFDESTRUCT) is MEDIUM — code injection deployment pattern. EXTCODECOPY + CREATE2 + SELFDESTRUCT remains METAMORPHIC (CRITICAL).
- **Permit2 warning completeness**: Every `contextualRisk === 'CRITICAL'` path in `generateWarnings` must have a corresponding warning emission. The Permit2 branch (`type === 'permit'`) was previously missing.
- **Reentrancy: STATICCALL excluded**: STATICCALL is read-only by EVM spec — cannot cause reentrancy. Only CALL, DELEGATECALL, CALLCODE are checked for SSTORE-after-call pattern. Prevents false positives on ecrecover (STATICCALL to precompile) + nonce (SSTORE) patterns in smart wallets.
- **Set-based lookups**: All selector and comparison matching uses pre-computed `Set.has()` instead of `Array.includes()`. O(1) vs O(n) in hot paths (detectTokenSelectors, detectComparisonBranching, hasPush4Selector, detectErc4337Pattern).
- **EXTCODEHASH + EIP-7702**: EXTCODEHASH returns different values for delegated vs non-delegated EOAs. Contracts checking code hash may have unexpected behavior with EIP-7702 delegations.
- **ReentrancyGuard false positive (known)**: OpenZeppelin `nonReentrant` modifier produces SSTORE (mutex unlock) after external CALL. This triggers `detectReentrancyRisk`. Accepted for EIP-7702 context — delegation targets with CALL+SSTORE but no auth patterns are genuinely suspicious. Monitor user FP reports to calibrate.
- **ReadonlySet immutability**: All pre-computed Sets use `ReadonlySet<string>` type annotation to prevent accidental `.add()`/`.delete()` at compile time.
