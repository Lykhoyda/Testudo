/**
 * CONTENT SCRIPT
 * 
 * Runs in isolated content script context.
 * Bridges communication between:
 * - Injected script (page context) via window.postMessage
 * - Background script (extension context) via chrome.runtime.sendMessage
 * 
 * Also responsible for injecting the injected.js script into the page.
 */

// Inject the injected.js script into the page
function injectScript() {
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('injected.js');
  script.type = 'module';
  
  // Insert at document_start to ensure we intercept before any dApp code runs
  (document.head || document.documentElement).appendChild(script);
  
  script.onload = () => {
    script.remove(); // Clean up after injection
  };
}

// Inject immediately
injectScript();

// Listen for messages from injected script
window.addEventListener('message', async (event) => {
  // Only accept messages from same window
  if (event.source !== window) return;
  
  // Handle analysis request
  if (event.data?.type === 'TESTUDO_ANALYZE_REQUEST') {
    const { requestId, delegateAddress } = event.data;
    
    console.log('[Testudo Content] Received analysis request:', delegateAddress);
    
    try {
      // Send to background script for analysis
      const result = await chrome.runtime.sendMessage({
        type: 'ANALYZE_DELEGATION',
        delegateAddress,
      });
      
      console.log('[Testudo Content] Analysis result:', result);
      
      // Send result back to injected script
      window.postMessage({
        type: 'TESTUDO_ANALYSIS_RESULT',
        requestId,
        result,
      }, '*');
      
    } catch (error) {
      console.error('[Testudo Content] Analysis error:', error);
      
      // Send error result
      window.postMessage({
        type: 'TESTUDO_ANALYSIS_RESULT',
        requestId,
        result: {
          risk: 'UNKNOWN',
          threats: [],
          address: delegateAddress,
          error: String(error),
        },
      }, '*');
    }
  }
});

// Listen for messages from background script (e.g., for popup updates)
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'GET_PAGE_STATUS') {
    // Could be used by popup to show current page status
    sendResponse({ 
      active: true,
      url: window.location.href,
    });
  }
  return true;
});

console.log('[Testudo Content] Content script loaded');

export {};
