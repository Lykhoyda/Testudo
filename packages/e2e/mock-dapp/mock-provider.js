/**
 * Mock Ethereum Provider for E2E Testing
 *
 * Provides a minimal window.ethereum that triggers EIP-7702 delegation requests.
 * The injected script from the extension will intercept these.
 */

// Known addresses from @testudo/core
const MALICIOUS_ADDRESS = '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b';
const SAFE_ADDRESS = '0x63c0c19a282a1b52b07dd5a65b58948a07dae32b';

// Create EIP-7702 Authorization typed data
function createAuthorizationTypedData(delegateAddress) {
  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
      ],
      Authorization: [
        { name: 'chainId', type: 'uint256' },
        { name: 'address', type: 'address' },
        { name: 'nonce', type: 'uint256' },
      ],
    },
    primaryType: 'Authorization',
    domain: {
      name: 'EIP-7702 Authorization',
      version: '1',
      chainId: 1,
    },
    message: {
      chainId: '1',
      address: delegateAddress,
      nonce: '0',
    },
  };
}

// Mock ethereum provider
window.ethereum = {
  isMetaMask: true,

  request: async function(args) {
    console.log('[Mock Provider] Request:', args.method, args.params);

    if (args.method === 'eth_requestAccounts') {
      return ['0x1234567890123456789012345678901234567890'];
    }

    if (args.method === 'eth_signTypedData_v4') {
      // The extension's injected script will intercept this
      // and potentially show a warning modal
      const [account, typedDataString] = args.params;
      const typedData = typeof typedDataString === 'string'
        ? JSON.parse(typedDataString)
        : typedDataString;

      console.log('[Mock Provider] Typed data:', typedData);

      // Simulate successful signature if extension allows it
      return '0x' + '00'.repeat(65);
    }

    throw new Error(`Unsupported method: ${args.method}`);
  },
};

// Update provider status
document.getElementById('provider-status').textContent = 'Ready ✓';
document.getElementById('provider-status').style.color = '#27ae60';

// Result display helper
function showResult(message, isError = false) {
  const resultEl = document.getElementById('result');
  resultEl.textContent = message;
  resultEl.style.borderLeft = isError ? '3px solid #e74c3c' : '3px solid #27ae60';
}

// Sign malicious delegation button
document.getElementById('sign-malicious').addEventListener('click', async () => {
  showResult('Requesting signature for MALICIOUS delegation...');

  try {
    const typedData = createAuthorizationTypedData(MALICIOUS_ADDRESS);
    const result = await window.ethereum.request({
      method: 'eth_signTypedData_v4',
      params: [
        '0x1234567890123456789012345678901234567890',
        JSON.stringify(typedData),
      ],
    });
    showResult(`Signature received (user proceeded):\n${result}`);
  } catch (error) {
    showResult(`Blocked/Rejected:\n${error.message}`, true);
  }
});

// Sign safe delegation button
document.getElementById('sign-safe').addEventListener('click', async () => {
  showResult('Requesting signature for SAFE delegation...');

  try {
    const typedData = createAuthorizationTypedData(SAFE_ADDRESS);
    const result = await window.ethereum.request({
      method: 'eth_signTypedData_v4',
      params: [
        '0x1234567890123456789012345678901234567890',
        JSON.stringify(typedData),
      ],
    });
    showResult(`Signature received:\n${result}`);
  } catch (error) {
    showResult(`Error:\n${error.message}`, true);
  }
});

console.log('[Mock Provider] Initialized with EIP-7702 support');
