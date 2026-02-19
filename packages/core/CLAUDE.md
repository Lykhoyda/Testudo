# @testudo/core — Detection Engine

Pure, deterministic bytecode analysis library. No I/O in production detection path. MIT licensed.

## Architecture

```
src/
├── index.ts          # Public exports (all re-exports)
├── analyzer.ts       # Orchestrator: fetchBytecode → parse → detect → score → warnings
├── detectors.ts      # 7 pattern detectors (runAllDetectors)
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
- `WarningType` — 23 values (AUTO_FORWARDER, DELEGATE_CALL, ..., DEPLOYER_FRESH, etc.)
- `DetectionResults` — Raw detector output (booleans + TokenTransferAnalysis)
- `DeployerInfo` / `DeployerRiskAssessment` — Deployer reputation data

## Detection Pipeline

```
analyzeContract(address, options?)
  → fetchBytecode(address)        # viem getCode
  → parseBytecode(hex)            # Instruction[] with correct PUSH handling
  → runAllDetectors(instructions) # 7 detectors → DetectionResults
  → generateWarnings(results)     # DetectionResults → Warning[]
  → deriveRiskFromWarnings(warnings) # Warning[] → risk level + blocked flag
```

## Detectors (detectors.ts — 14 functions)

`runAllDetectors()` orchestrates all detectors and returns `DetectionResults`.

| Risk Category | Detection Functions | Looks For | Risk |
|---------------|-------------------|-----------|------|
| Auto-Forwarder | detectAutoForwarder | SELFBALANCE + CALL | CRITICAL |
| DelegateCall | detectDelegateCall | 0xF4 opcode | HIGH |
| SelfDestruct | detectSelfDestruct | 0xFF as opcode (not PUSH data) | HIGH |
| CREATE2 | detectCreate2 | 0xF5 opcode | MEDIUM |
| Metamorphic | CREATE2 + SELFDESTRUCT combined | Both present | CRITICAL |
| CHAINID | detectChainId | 0x46 + branching/comparison patterns | MEDIUM-HIGH |
| Token Transfer | detectTokenSelectors, detectEcrecover, detectMsgSenderCheck, detectNonceTracking, detectFallbackLocation, detectHardcodedDestination, analyzeTokenTransfers | ERC20/721/1155 selectors + auth patterns | Context-dependent |
| Unlimited Approval | detectUnlimitedApproval | PUSH32 all 0xFF | HIGH |

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
yarn workspace @testudo/core run test     # vitest, 190 tests
```

- viem is marked `external` in rolldown config (prevents double-bundling with extension)
- Output: ESM, ~25KB

## Tests (190 total)

| File | Count | Tests |
|------|-------|-------|
| parser.test.ts | 9 | PUSH opcode handling, edge cases |
| detectors.test.ts | 103 | All detectors with real bytecode fixtures |
| malicious-db.test.ts | 8 | Known address lookups |
| integration.test.ts | 46 | Full pipeline with real contracts |
| deployer-risk.test.ts | 22 | Risk matrix scoring |

## Important Patterns

- **PUSH data vs opcodes**: `0x60FF` is PUSH1 pushing `0xFF` (data), NOT SELFDESTRUCT. Parser skips N bytes after PUSH opcodes.
- **EIP-712 false positive**: CHAINID followed by KECCAK256 = EIP-712 signature hashing, not cross-chain attack. Detector marks as SAFE.
- **Risk escalation**: 2+ MEDIUM warnings → HIGH (not CRITICAL, avoids false positives on smart wallets).
- **Fail-open**: Analysis errors return UNKNOWN risk with `blocked: false`.
