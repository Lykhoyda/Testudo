/**
 * BACKGROUND SERVICE WORKER
 * 
 * Handles:
 * - Analysis requests from content script
 * - Fetching bytecode from RPC
 * - Running detection engine
 * - Caching results
 */

// ============================================
// TYPES
// ============================================

interface Instruction {
  opcode: string;
  byteIndex: number;
  data?: Uint8Array;
  size?: number;
}

interface AnalysisResult {
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  threats: string[];
  address: string;
  blocked: boolean;
  cached?: boolean;
}

interface KnownMaliciousContract {
  type: string;
  source: string;
  stolen: string;
  description: string;
}

// ============================================
// KNOWN MALICIOUS DATABASE
// ============================================

const KNOWN_MALICIOUS: Record<string, KnownMaliciousContract> = {
  '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b': {
    type: 'ETH_AUTO_FORWARDER',
    source: 'SunSec Report May 2025',
    stolen: '$2.3M+',
    description: 'Auto-redirects all incoming ETH to attacker',
  },
  '0xa85d90b8febc092e11e75bf8f93a7090e2ed04de': {
    type: 'INFERNO_DRAINER',
    source: 'SlowMist Analysis May 2025',
    stolen: '$146K+',
    description: 'Batch authorization exploit',
  },
  '0x0000db5c8b030ae20308ac975898e09741e70000': {
    type: 'INFERNO_DRAINER',
    source: 'SlowMist Analysis May 2025',
    stolen: 'Part of $12M campaign',
    description: 'Fraudulent batch approval address',
  },
  '0x00008c22f9f6f3101533f520e229bbb54be90000': {
    type: 'INFERNO_DRAINER',
    source: 'SlowMist Analysis May 2025',
    stolen: 'Part of $12M campaign',
    description: 'Fraudulent batch approval address',
  },
};

// MetaMask legitimate delegator - whitelist
const KNOWN_SAFE: Set<string> = new Set([
  '0x63c0c19a282a1b52b07dd5a65b58948a07dae32b', // MetaMask official
]);

// ============================================
// OPCODE CONSTANTS
// ============================================

const OPCODES: Record<string, string> = {
  'F1': 'CALL',
  'F4': 'DELEGATECALL',
  '47': 'SELFBALANCE',
  '7F': 'PUSH32',
  'FF': 'SELFDESTRUCT',
  'F5': 'CREATE2',
};

// ============================================
// CACHE
// ============================================

const analysisCache = new Map<string, { result: AnalysisResult; timestamp: number }>();
const CACHE_TTL = 60 * 60 * 1000; // 1 hour

// ============================================
// RPC CONFIGURATION
// ============================================

const RPC_URL = 'https://eth.llamarpc.com';

// ============================================
// BYTECODE FETCHER
// ============================================

async function fetchBytecode(address: string): Promise<string | null> {
  try {
    const response = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_getCode',
        params: [address, 'latest'],
      }),
    });

    const data = await response.json();
    
    if (data.result === '0x' || data.result === '0x0') {
      return null;
    }
    
    return data.result;
  } catch (error) {
    console.error('[Testudo Background] RPC error:', error);
    return null;
  }
}

// ============================================
// BYTECODE PARSER
// ============================================

function parseBytecode(bytecode: string): Instruction[] {
  const cleanBytecode = bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode;
  const bytes = new Uint8Array(
    cleanBytecode.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
  );

  let byteIndex = 0;
  const instructions: Instruction[] = [];

  while (byteIndex < bytes.length) {
    const byte = bytes[byteIndex] as number;
    const code = byte.toString(16).padStart(2, '0').toUpperCase();

    // PUSH1-PUSH32 (0x60-0x7F)
    if (byte >= 0x60 && byte <= 0x7f) {
      const pushSize = byte - 0x5f;
      const data = bytes.slice(byteIndex + 1, byteIndex + 1 + pushSize);
      instructions.push({
        opcode: `PUSH${pushSize}`,
        byteIndex,
        data,
        size: pushSize + 1,
      });
      byteIndex += pushSize + 1;
    } else {
      const opcode = OPCODES[code] || code;
      instructions.push({
        opcode,
        byteIndex,
        size: 1,
      });
      byteIndex += 1;
    }
  }

  return instructions;
}

// ============================================
// DETECTORS
// ============================================

function detectAutoForwarder(instructions: Instruction[]): boolean {
  let hasSelfBalance = false;
  let hasCall = false;

  for (const instruction of instructions) {
    if (instruction.opcode === 'SELFBALANCE') hasSelfBalance = true;
    if (instruction.opcode === 'CALL') hasCall = true;
  }

  return hasSelfBalance && hasCall;
}

function detectDelegateCall(instructions: Instruction[]): boolean {
  return instructions.some(i => i.opcode === 'DELEGATECALL');
}

function detectSelfDestruct(instructions: Instruction[]): boolean {
  return instructions.some(i => i.opcode === 'SELFDESTRUCT');
}

function detectUnlimitedApproval(instructions: Instruction[]): boolean {
  for (const instruction of instructions) {
    if (instruction.opcode === 'PUSH32' && instruction.data) {
      if (instruction.data.every((byte) => byte === 0xff)) {
        return true;
      }
    }
  }
  return false;
}

function runAllDetectors(instructions: Instruction[]) {
  return {
    hasAutoForwarder: detectAutoForwarder(instructions),
    isDelegatedCall: detectDelegateCall(instructions),
    hasSelfDestruct: detectSelfDestruct(instructions),
    hasUnlimitedApprovals: detectUnlimitedApproval(instructions),
  };
}

// ============================================
// MAIN ANALYSIS FUNCTION
// ============================================

async function analyzeContract(address: string): Promise<AnalysisResult> {
  const normalizedAddress = address.toLowerCase();
  
  // Check cache first
  const cached = analysisCache.get(normalizedAddress);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    console.log('[Testudo Background] Cache hit:', normalizedAddress);
    return { ...cached.result, cached: true };
  }

  // Check whitelist
  if (KNOWN_SAFE.has(normalizedAddress)) {
    const result: AnalysisResult = {
      risk: 'LOW',
      threats: [],
      address: normalizedAddress,
      blocked: false,
    };
    analysisCache.set(normalizedAddress, { result, timestamp: Date.now() });
    return result;
  }

  // Check known malicious database
  const knownMalicious = KNOWN_MALICIOUS[normalizedAddress];
  if (knownMalicious) {
    const result: AnalysisResult = {
      risk: 'CRITICAL',
      threats: [knownMalicious.type],
      address: normalizedAddress,
      blocked: true,
    };
    analysisCache.set(normalizedAddress, { result, timestamp: Date.now() });
    return result;
  }

  // Fetch and analyze bytecode
  try {
    const bytecode = await fetchBytecode(normalizedAddress);
    
    if (!bytecode) {
      return {
        risk: 'UNKNOWN',
        threats: ['No bytecode found'],
        address: normalizedAddress,
        blocked: false,
      };
    }

    const instructions = parseBytecode(bytecode);
    const detectionResults = runAllDetectors(instructions);
    
    // Collect detected threats
    const threats: string[] = [];
    if (detectionResults.hasAutoForwarder) threats.push('hasAutoForwarder');
    if (detectionResults.isDelegatedCall) threats.push('isDelegatedCall');
    if (detectionResults.hasSelfDestruct) threats.push('hasSelfDestruct');
    if (detectionResults.hasUnlimitedApprovals) threats.push('hasUnlimitedApprovals');

    // Calculate risk
    let risk: AnalysisResult['risk'] = 'LOW';
    let blocked = false;

    if (threats.length > 0) {
      // CRITICAL: auto-forwarder or multiple threats
      if (detectionResults.hasAutoForwarder || threats.length >= 2) {
        risk = 'CRITICAL';
        blocked = true;
      }
      // HIGH: single dangerous pattern
      else if (detectionResults.hasSelfDestruct || detectionResults.isDelegatedCall) {
        risk = 'HIGH';
        blocked = true;
      }
      // MEDIUM: unlimited approvals alone
      else {
        risk = 'MEDIUM';
      }
    }

    const result: AnalysisResult = {
      risk,
      threats,
      address: normalizedAddress,
      blocked,
    };

    // Cache result
    analysisCache.set(normalizedAddress, { result, timestamp: Date.now() });
    
    return result;

  } catch (error) {
    console.error('[Testudo Background] Analysis error:', error);
    return {
      risk: 'UNKNOWN',
      threats: ['Analysis failed'],
      address: normalizedAddress,
      blocked: false,
    };
  }
}

// ============================================
// MESSAGE HANDLER
// ============================================

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'ANALYZE_DELEGATION') {
    console.log('[Testudo Background] Analyzing:', message.delegateAddress);
    
    analyzeContract(message.delegateAddress)
      .then(result => {
        console.log('[Testudo Background] Result:', result);
        sendResponse(result);
      })
      .catch(error => {
        console.error('[Testudo Background] Error:', error);
        sendResponse({
          risk: 'UNKNOWN',
          threats: ['Analysis error'],
          address: message.delegateAddress,
          blocked: false,
        });
      });
    
    return true; // Keep channel open for async response
  }
  
  if (message.type === 'GET_STATS') {
    sendResponse({
      cacheSize: analysisCache.size,
      knownMalicious: Object.keys(KNOWN_MALICIOUS).length,
      knownSafe: KNOWN_SAFE.size,
    });
    return true;
  }
});

// ============================================
// INITIALIZATION
// ============================================

console.log('[Testudo Background] 🛡️ Service worker started');
console.log(`[Testudo Background] Known malicious: ${Object.keys(KNOWN_MALICIOUS).length}`);
console.log(`[Testudo Background] Known safe: ${KNOWN_SAFE.size}`);

export {};
