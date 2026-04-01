export const WARNING_STYLES = `
:host {
  all: initial;
  display: block !important;
  position: static !important;
  visibility: visible !important;
}

@keyframes testudo-fade-in {
  from { opacity: 0; }
  to { opacity: 1; }
}

@keyframes testudo-modal-in {
  from { opacity: 0; transform: translateY(8px) scale(0.98); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}

@keyframes testudo-scan-line {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(200%); }
}

@keyframes testudo-pulse-ring {
  0% { box-shadow: 0 0 0 0 rgba(255, 59, 92, 0.35); }
  70% { box-shadow: 0 0 0 10px rgba(255, 59, 92, 0); }
  100% { box-shadow: 0 0 0 0 rgba(255, 59, 92, 0); }
}

@keyframes testudo-pulse-ring-amber {
  0% { box-shadow: 0 0 0 0 rgba(255, 170, 44, 0.25); }
  70% { box-shadow: 0 0 0 10px rgba(255, 170, 44, 0); }
  100% { box-shadow: 0 0 0 0 rgba(255, 170, 44, 0); }
}

@keyframes testudo-spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

@keyframes testudo-slide-in {
  from { transform: translateX(120%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}

@keyframes testudo-loading-slide {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(100%); }
}

#testudo-warning-overlay *,
#testudo-warning-overlay *::before,
#testudo-warning-overlay *::after {
  box-sizing: border-box;
}

#testudo-warning-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(7, 7, 12, 0.88);
  backdrop-filter: blur(12px) saturate(1.1);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 999999;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  animation: testudo-fade-in 0.25s ease;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

.testudo-modal {
  background: #0c0c14;
  border-radius: 10px;
  border: 1px solid rgba(255, 59, 92, 0.12);
  max-width: 440px;
  width: 92%;
  max-height: 90vh;
  color: #c8c8d8;
  box-shadow:
    0 0 0 1px rgba(255, 59, 92, 0.04),
    0 24px 48px -8px rgba(0, 0, 0, 0.8),
    0 0 80px -20px rgba(255, 59, 92, 0.06);
  overflow: hidden;
  animation: testudo-modal-in 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  display: flex;
  flex-direction: column;
  position: relative;
}

.testudo-modal::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent 0%, #ff3b5c 30%, #ff3b5c 70%, transparent 100%);
  opacity: 0.7;
}

.testudo-modal::after {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  width: 40%;
  height: 2px;
  background: linear-gradient(90deg, transparent, rgba(255, 59, 92, 0.8), transparent);
  animation: testudo-scan-line 3s linear infinite;
  opacity: 0.4;
}

.testudo-material-icon {
  font-family: 'Material Symbols Outlined';
  font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
  font-style: normal;
  display: inline-block;
  line-height: 1;
  text-transform: none;
  letter-spacing: normal;
  word-wrap: normal;
  white-space: nowrap;
  direction: ltr;
  -webkit-font-smoothing: antialiased;
}

/* ── Header ── */

.testudo-header {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 28px 24px 12px;
  gap: 14px;
  flex-shrink: 0;
  position: relative;
}

.testudo-header-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 52px;
  height: 52px;
  border-radius: 10px;
  background: rgba(255, 59, 92, 0.06);
  border: 1px solid rgba(255, 59, 92, 0.15);
  color: #ff3b5c;
  animation: testudo-pulse-ring 2s ease-in-out infinite;
}

.testudo-header-icon .testudo-material-icon {
  font-size: 26px;
}

.testudo-header-text {
  text-align: center;
}

.testudo-title {
  font-family: 'Roboto Mono', ui-monospace, monospace;
  font-size: 15px;
  font-weight: 700;
  color: #f0f0f5;
  margin: 0 0 6px 0;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  line-height: 1.3;
}

.testudo-subtitle {
  font-size: 13px;
  color: #6e6e8a;
  margin: 0;
  line-height: 1.5;
  max-width: 340px;
}

.testudo-subtitle strong {
  color: #c8c8d8;
  font-weight: 600;
}

/* ── Alert Box ── */

.testudo-alert {
  margin: 4px 16px 0;
  position: relative;
  overflow: hidden;
  border-radius: 6px;
  border: 1px solid rgba(255, 59, 92, 0.2);
  background: rgba(255, 59, 92, 0.04);
  padding: 14px 16px;
}

.testudo-alert::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(255, 59, 92, 0.35), transparent);
}

.testudo-alert-header {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #ff3b5c;
  position: relative;
}

.testudo-alert-header .testudo-material-icon {
  font-size: 16px;
}

.testudo-alert-title {
  font-family: 'Roboto Mono', ui-monospace, monospace;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}

.testudo-alert-medium {
  border-color: rgba(255, 170, 44, 0.2);
  background: rgba(255, 170, 44, 0.03);
}

.testudo-alert-medium::before {
  background: linear-gradient(90deg, transparent, rgba(255, 170, 44, 0.35), transparent);
}

.testudo-alert-medium .testudo-alert-header {
  color: #ffaa2c;
}

.testudo-alert-description {
  color: #6e6e8a;
  font-size: 13px;
  font-weight: 400;
  line-height: 1.6;
  margin-top: 6px;
  position: relative;
}

/* ── Context Details & Intent ── */

.testudo-address-section {
  margin: 8px 16px;
}

.testudo-intent-action {
  font-size: 13px;
  color: #6e6e8a;
  line-height: 1.6;
  margin-bottom: 8px;
  padding: 0 4px;
}

.testudo-address-box {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #12121e;
  border-radius: 6px;
  padding: 10px 14px;
  border: 1px solid rgba(255, 255, 255, 0.04);
  transition: border-color 0.15s;
}

.testudo-address-box:hover {
  border-color: rgba(255, 255, 255, 0.08);
}

.testudo-address-label {
  font-family: 'Roboto Mono', ui-monospace, monospace;
  font-size: 9px;
  font-weight: 600;
  color: #3e3e55;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.testudo-address-value {
  display: flex;
  align-items: center;
  gap: 8px;
}

.testudo-address-text {
  font-family: 'Roboto Mono', ui-monospace, monospace;
  font-size: 13px;
  color: #c8c8d8;
  letter-spacing: 0.01em;
}

.testudo-copy-btn {
  background: none;
  border: none;
  color: #3e3e55;
  cursor: pointer;
  padding: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: color 0.15s;
  border-radius: 4px;
}

.testudo-copy-btn:hover {
  color: #6e6e8a;
  background: rgba(255, 255, 255, 0.04);
}

.testudo-copy-btn .testudo-material-icon {
  font-size: 14px;
}

/* ── Threats ── */

.testudo-threats {
  padding: 12px 16px;
  margin-top: 4px;
  overflow-y: auto;
  max-height: 200px;
  flex-shrink: 1;
}

.testudo-threats-title {
  font-family: 'Roboto Mono', ui-monospace, monospace;
  font-size: 9px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: #3e3e55;
  margin-bottom: 8px;
  padding: 0 2px;
}

.testudo-threat-item {
  display: flex;
  align-items: center;
  gap: 12px;
  background: #12121e;
  border-radius: 6px;
  padding: 10px 12px;
  border: 1px solid rgba(255, 255, 255, 0.03);
  margin-bottom: 6px;
}

.testudo-threat-item:last-child {
  margin-bottom: 0;
}

.testudo-threat-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 30px;
  border-radius: 6px;
  background: rgba(255, 170, 44, 0.06);
  color: #ffaa2c;
  flex-shrink: 0;
}

.testudo-threat-icon .testudo-material-icon {
  font-size: 16px;
}

.testudo-threat-content {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.testudo-threat-name {
  font-size: 13px;
  font-weight: 600;
  color: #c8c8d8;
  line-height: 1.3;
}

.testudo-threat-desc {
  font-size: 11px;
  color: #3e3e55;
  margin-top: 2px;
  line-height: 1.4;
}

/* ── Buttons ── */

.testudo-buttons {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 12px 16px 20px;
  background: #0c0c14;
  flex-shrink: 0;
  position: relative;
}

.testudo-buttons::before {
  content: '';
  position: absolute;
  top: 0;
  left: 16px;
  right: 16px;
  height: 1px;
  background: rgba(255, 255, 255, 0.04);
}

.testudo-btn-cancel {
  width: 100%;
  background: linear-gradient(180deg, #00c77d 0%, #00a366 100%);
  color: white;
  border: none;
  border-radius: 8px;
  padding: 14px 20px;
  font-family: 'Roboto Mono', ui-monospace, monospace;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  box-shadow:
    0 1px 2px rgba(0, 0, 0, 0.4),
    inset 0 1px 0 rgba(255, 255, 255, 0.1);
  transition: all 0.15s;
}

.testudo-btn-cancel:hover {
  background: linear-gradient(180deg, #00e599 0%, #00c77d 100%);
  box-shadow:
    0 2px 12px rgba(0, 199, 125, 0.25),
    inset 0 1px 0 rgba(255, 255, 255, 0.15);
}

.testudo-btn-cancel:active {
  transform: scale(0.985);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.4);
}

.testudo-btn-cancel .testudo-material-icon {
  font-size: 18px;
}

.testudo-secondary-actions {
  display: flex;
  align-items: center;
  justify-content: center;
}

.testudo-btn-link {
  background: none;
  border: none;
  color: #3e3e55;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  padding: 6px 12px;
  transition: color 0.15s;
  border-radius: 6px;
}

.testudo-btn-link:hover {
  color: #6e6e8a;
  background: rgba(255, 255, 255, 0.03);
}

.testudo-btn-danger {
  display: flex;
  align-items: center;
  gap: 4px;
  background: none;
  border: none;
  color: #3e3e55;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  padding: 6px 12px;
  transition: all 0.15s;
  border-radius: 6px;
}

.testudo-btn-danger:hover {
  color: #ff3b5c;
  background: rgba(255, 59, 92, 0.04);
}

.testudo-btn-danger .testudo-material-icon {
  font-size: 14px;
  transition: transform 0.15s;
}

.testudo-btn-danger:hover .testudo-material-icon {
  transform: translateX(2px);
}

/* ── eth_sign Confirmation ── */

.testudo-confirm-section {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.testudo-confirm-label {
  font-family: 'Roboto Mono', ui-monospace, monospace;
  font-size: 10px;
  color: #3e3e55;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

.testudo-confirm-input {
  width: 100%;
  background: #12121e;
  border: 1px solid rgba(255, 59, 92, 0.15);
  border-radius: 6px;
  padding: 10px 12px;
  font-size: 13px;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  color: #c8c8d8;
  outline: none;
  transition: border-color 0.15s;
  box-sizing: border-box;
}

.testudo-confirm-input:focus {
  border-color: rgba(255, 59, 92, 0.4);
  box-shadow: 0 0 0 2px rgba(255, 59, 92, 0.06);
}

.testudo-confirm-input::placeholder {
  color: rgba(62, 62, 85, 0.6);
}

.testudo-btn-danger-confirm {
  width: 100%;
  background: rgba(255, 59, 92, 0.04);
  color: rgba(255, 59, 92, 0.3);
  border: 1px solid rgba(255, 59, 92, 0.08);
  border-radius: 8px;
  padding: 12px 20px;
  font-family: 'Roboto Mono', ui-monospace, monospace;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  cursor: not-allowed;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  transition: all 0.15s;
}

.testudo-btn-danger-confirm.enabled {
  background: rgba(255, 59, 92, 0.08);
  color: #ff3b5c;
  border-color: rgba(255, 59, 92, 0.25);
  cursor: pointer;
}

.testudo-btn-danger-confirm.enabled:hover {
  background: rgba(255, 59, 92, 0.15);
  border-color: rgba(255, 59, 92, 0.4);
}

/* ── Loading ── */

.testudo-spin {
  animation: testudo-spin 1.5s linear infinite;
}

.testudo-loading-icon {
  background: rgba(0, 229, 153, 0.04);
  border-color: rgba(0, 229, 153, 0.12);
  color: #00e599;
  animation: none;
}

.testudo-loading-bar-container {
  margin: 12px 16px;
  height: 2px;
  border-radius: 1px;
  background: rgba(0, 229, 153, 0.06);
  overflow: hidden;
}

.testudo-loading-bar {
  height: 100%;
  width: 50%;
  border-radius: 1px;
  background: linear-gradient(90deg, transparent, #00e599, transparent);
  animation: testudo-loading-slide 1.4s ease-in-out infinite;
}

/* ── Toasts (shared) ── */

.testudo-toast,
.testudo-toast-unknown {
  position: fixed;
  bottom: 16px;
  right: 16px;
  background: #0c0c14;
  border-radius: 8px;
  padding: 14px 16px;
  color: #c8c8d8;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  z-index: 999998;
  max-width: 360px;
  box-shadow: 0 12px 32px -4px rgba(0, 0, 0, 0.7);
  animation: testudo-slide-in 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  display: flex;
  gap: 10px;
  align-items: flex-start;
  -webkit-font-smoothing: antialiased;
}

.testudo-toast-icon,
.testudo-toast-unknown-icon {
  font-family: 'Material Symbols Outlined';
  font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
  font-size: 20px;
  flex-shrink: 0;
  margin-top: 1px;
}

.testudo-toast-content,
.testudo-toast-unknown-content {
  flex: 1;
}

.testudo-toast-title,
.testudo-toast-unknown-title {
  font-weight: 600;
  font-size: 13px;
  display: flex;
  align-items: center;
  gap: 5px;
}

.testudo-toast-text,
.testudo-toast-unknown-text {
  font-size: 12px;
  color: #3e3e55;
  margin-top: 4px;
  line-height: 1.5;
}

.testudo-toast-dismiss,
.testudo-toast-unknown-dismiss {
  background: none;
  border: none;
  color: #3e3e55;
  cursor: pointer;
  font-size: 11px;
  margin-top: 6px;
  padding: 3px 8px;
  border-radius: 4px;
  transition: background 0.15s, color 0.15s;
  font-weight: 500;
}

.testudo-toast-dismiss:hover,
.testudo-toast-unknown-dismiss:hover {
  background: rgba(255, 255, 255, 0.04);
  color: #6e6e8a;
}

/* ── Info Toast (specifics) ── */

.testudo-toast {
  border: 1px solid rgba(255, 170, 44, 0.15);
  box-shadow:
    0 0 0 1px rgba(255, 170, 44, 0.04),
    0 12px 32px -4px rgba(0, 0, 0, 0.7);
}

.testudo-toast::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(255, 170, 44, 0.25), transparent);
}

.testudo-toast-icon {
  color: #ffaa2c;
}

.testudo-toast-title {
  color: #ffaa2c;
}

.testudo-toast-title .testudo-toast-icon-inline {
  font-family: 'Material Symbols Outlined';
  font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
  font-size: 14px;
}

/* ── Unknown Toast (specifics) ── */

.testudo-toast-unknown {
  border: 1px solid rgba(255, 255, 255, 0.06);
}

.testudo-toast-unknown-icon {
  color: #4a4a6a;
}

.testudo-toast-unknown-title {
  color: #6e6e8a;
}

.testudo-toast-unknown-address {
  font-family: 'Roboto Mono', monospace;
  font-size: 11px;
  color: #3e3e55;
  margin-top: 5px;
}

/* ── Focus States (keyboard navigation) ── */

.testudo-btn-cancel:focus-visible,
.testudo-btn-danger-confirm:focus-visible {
  outline: 2px solid #00e599;
  outline-offset: 2px;
}

.testudo-btn-link:focus-visible,
.testudo-btn-danger:focus-visible,
.testudo-copy-btn:focus-visible,
.testudo-toast-dismiss:focus-visible,
.testudo-toast-unknown-dismiss:focus-visible {
  outline: 2px solid #00e599;
  outline-offset: 1px;
  border-radius: 4px;
}

.testudo-confirm-input:focus-visible {
  outline: none;
  border-color: rgba(0, 229, 153, 0.5);
  box-shadow: 0 0 0 2px rgba(0, 229, 153, 0.1);
}

/* ── Utility Classes ── */

.testudo-text-danger {
  color: #ff3b5c;
}

/* ── Reduced Motion ── */

@media (prefers-reduced-motion: reduce) {
  #testudo-warning-overlay,
  #testudo-warning-overlay *,
  #testudo-warning-overlay *::before,
  #testudo-warning-overlay *::after,
  .testudo-toast,
  .testudo-toast-unknown {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
`;

export function injectWarningStyles(root: ShadowRoot | HTMLElement = document.head): void {
	if (root.querySelector('#testudo-warning-styles')) return;
	const style = document.createElement('style');
	style.id = 'testudo-warning-styles';
	style.textContent = WARNING_STYLES;
	root.appendChild(style);
}
