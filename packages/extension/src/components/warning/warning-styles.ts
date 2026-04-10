export const WARNING_STYLES = `
:host {
  all: initial;
  display: block !important;
  position: static !important;
  visibility: visible !important;
}

/* ── Design Tokens — Quiet Confidence ── */
#testudo-warning-overlay {
  --surface: #141416;
  --surface-raised: #1c1c1f;
  --border-strong: rgba(255, 255, 255, 0.14);
  --border-subtle: rgba(255, 255, 255, 0.08);

  --text: #fafafa;
  --text-secondary: #e5e5e7;
  --text-muted: #a0a0a8;
  --text-dim: #5a5a60;

  --brand: #1a9b8c;
  --brand-hover: #26b5a4;
  --brand-ink: #03150f;

  --danger: #dc2626;
  --danger-bg: rgba(220, 38, 38, 0.1);
  --danger-border: rgba(220, 38, 38, 0.3);

  --warn: #f59e0b;
  --warn-bg: rgba(245, 158, 11, 0.1);

  --font-sans: 'Geist', -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
  --font-mono: 'Geist Mono', ui-monospace, monospace;
}

@keyframes testudo-fade-in {
  from { opacity: 0; }
  to { opacity: 1; }
}

@keyframes testudo-modal-in {
  from { opacity: 0; transform: translateY(8px) scale(0.98); }
  to { opacity: 1; transform: translateY(0) scale(1); }
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
  background: rgba(10, 10, 11, 0.85);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 999999;
  font-family: var(--font-sans);
  animation: testudo-fade-in 0.25s ease;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: var(--text-secondary);
}

/* ── Modal Shell ── */

.testudo-modal {
  background: var(--surface);
  border-radius: 14px;
  border: 1px solid var(--border-strong);
  width: 440px;
  max-width: 92%;
  max-height: 90vh;
  color: var(--text-secondary);
  box-shadow: 0 24px 48px -8px rgba(0, 0, 0, 0.6);
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
  height: 3px;
  background: var(--danger);
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

.testudo-header,
.testudo-modal-header {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  padding: 24px 24px 14px;
  gap: 14px;
  flex-shrink: 0;
  position: relative;
}

.testudo-header-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  border-radius: 8px;
  background: var(--danger-bg);
  border: 1px solid var(--danger-border);
  color: var(--danger);
}

.testudo-header-icon .testudo-material-icon {
  font-size: 22px;
}

.testudo-header-text {
  text-align: left;
}

.testudo-title {
  font-family: var(--font-sans);
  font-size: 22px;
  font-weight: 600;
  color: var(--text);
  margin: 0 0 6px 0;
  letter-spacing: -0.02em;
  line-height: 1.2;
}

.testudo-subtitle {
  font-size: 13px;
  font-weight: 400;
  color: var(--text-muted);
  margin: 0;
  line-height: 1.55;
  max-width: 360px;
}

.testudo-subtitle strong {
  color: var(--text-secondary);
  font-weight: 600;
}

.testudo-intent-headline {
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
  line-height: 1.5;
  margin: 0;
}

/* ── Modal Body & Footer ── */

.testudo-modal-body {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 0 24px;
  overflow-y: auto;
  flex-shrink: 1;
}

.testudo-modal-footer {
  padding: 14px 24px 20px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  flex-shrink: 0;
}

/* ── Alert Box ── */

.testudo-alert,
.testudo-alert-box {
  margin: 0 24px;
  position: relative;
  border-radius: 10px;
  border: 1px solid var(--danger-border);
  background: var(--danger-bg);
  padding: 14px 16px;
}

.testudo-alert-header {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--danger);
}

.testudo-alert-header .testudo-material-icon {
  font-size: 16px;
}

.testudo-alert-title {
  font-family: var(--font-sans);
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--danger);
}

.testudo-alert-subtitle {
  font-size: 12px;
  font-weight: 500;
  color: var(--text-muted);
  letter-spacing: 0.02em;
}

.testudo-alert-description {
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 400;
  line-height: 1.55;
  margin-top: 6px;
}

/* Severity variants */
.testudo-alert.critical,
.testudo-alert-box.critical {
  border-color: var(--danger-border);
  background: var(--danger-bg);
}

.testudo-alert.critical .testudo-alert-header,
.testudo-alert.critical .testudo-alert-title,
.testudo-alert-box.critical .testudo-alert-header,
.testudo-alert-box.critical .testudo-alert-title {
  color: var(--danger);
}

.testudo-alert.high,
.testudo-alert-box.high {
  border-color: var(--danger-border);
  background: var(--danger-bg);
}

.testudo-alert.high .testudo-alert-header,
.testudo-alert.high .testudo-alert-title,
.testudo-alert-box.high .testudo-alert-header,
.testudo-alert-box.high .testudo-alert-title {
  color: var(--danger);
}

.testudo-alert.medium,
.testudo-alert-medium,
.testudo-alert-box.medium {
  border-color: rgba(245, 158, 11, 0.3);
  background: var(--warn-bg);
}

.testudo-alert.medium .testudo-alert-header,
.testudo-alert.medium .testudo-alert-title,
.testudo-alert-medium .testudo-alert-header,
.testudo-alert-medium .testudo-alert-title,
.testudo-alert-box.medium .testudo-alert-header,
.testudo-alert-box.medium .testudo-alert-title {
  color: var(--warn);
}

.testudo-alert.low,
.testudo-alert-box.low {
  border-color: var(--border-strong);
  background: var(--surface-raised);
}

.testudo-alert.low .testudo-alert-header,
.testudo-alert.low .testudo-alert-title,
.testudo-alert-box.low .testudo-alert-header,
.testudo-alert-box.low .testudo-alert-title {
  color: var(--text-muted);
}

/* ── Context & Address Section ── */

.testudo-address-section {
  margin: 0 24px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.testudo-intent-action {
  font-size: 13px;
  font-weight: 400;
  color: var(--text-secondary);
  line-height: 1.55;
  margin-bottom: 4px;
  padding: 0 2px;
}

.testudo-context {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin: 0 24px;
}

.testudo-context-label {
  font-family: var(--font-sans);
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--text-dim);
}

.testudo-context-value {
  font-size: 13px;
  font-weight: 400;
  color: var(--text-secondary);
  line-height: 1.5;
}

.testudo-address-box {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--surface-raised);
  border-radius: 10px;
  padding: 12px 14px;
  border: 1px solid var(--border-subtle);
  transition: border-color 0.15s;
}

.testudo-address-box:hover {
  border-color: var(--border-strong);
}

.testudo-address-label {
  font-family: var(--font-sans);
  font-size: 11px;
  font-weight: 500;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.testudo-address-value {
  display: flex;
  align-items: center;
  gap: 8px;
}

.testudo-address-text {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--text-secondary);
  letter-spacing: 0.01em;
}

.testudo-copy-btn {
  background: none;
  border: none;
  color: var(--text-dim);
  cursor: pointer;
  padding: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: color 0.15s, background 0.15s;
  border-radius: 4px;
}

.testudo-copy-btn:hover {
  color: var(--text-muted);
  background: rgba(255, 255, 255, 0.04);
}

.testudo-copy-btn .testudo-material-icon {
  font-size: 14px;
}

/* ── Threat List ── */

.testudo-threats,
.testudo-threat-list {
  padding: 0 24px;
  margin: 0;
  overflow-y: auto;
  max-height: 220px;
  flex-shrink: 1;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.testudo-threats-title {
  font-family: var(--font-sans);
  font-size: 11px;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-dim);
  margin-bottom: 4px;
  padding: 0 2px;
}

.testudo-threat-item {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  background: var(--surface-raised);
  border-radius: 10px;
  padding: 12px 14px;
  border: 1px solid var(--border-subtle);
}

.testudo-threat-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: var(--warn-bg);
  color: var(--warn);
  flex-shrink: 0;
}

.testudo-threat-icon.critical,
.testudo-threat-icon.high {
  background: var(--danger-bg);
  color: var(--danger);
}

.testudo-threat-icon.medium {
  background: var(--warn-bg);
  color: var(--warn);
}

.testudo-threat-icon.low {
  background: var(--surface-raised);
  color: var(--text-muted);
}

.testudo-threat-icon .testudo-material-icon {
  font-size: 18px;
}

.testudo-threat-content {
  display: flex;
  flex-direction: column;
  min-width: 0;
  flex: 1;
  gap: 2px;
}

.testudo-threat-name,
.testudo-threat-title {
  font-family: var(--font-sans);
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  line-height: 1.35;
  letter-spacing: -0.005em;
}

.testudo-threat-desc {
  font-size: 12px;
  font-weight: 400;
  color: var(--text-dim);
  line-height: 1.5;
}

/* ── Buttons ── */

.testudo-buttons {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 14px 24px 20px;
  background: var(--surface);
  flex-shrink: 0;
  position: relative;
}

.testudo-buttons::before {
  content: '';
  position: absolute;
  top: 0;
  left: 24px;
  right: 24px;
  height: 1px;
  background: var(--border-subtle);
}

.testudo-btn {
  width: 100%;
  border-radius: 10px;
  padding: 12px 18px;
  font-family: var(--font-sans);
  font-size: 13px;
  font-weight: 500;
  letter-spacing: 0;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  transition: background 0.15s, border-color 0.15s, color 0.15s;
  border: 1px solid transparent;
}

.testudo-btn-cancel {
  width: 100%;
  background: var(--brand);
  color: var(--brand-ink);
  border: 1px solid var(--brand);
  border-radius: 10px;
  padding: 12px 18px;
  font-family: var(--font-sans);
  font-size: 13px;
  font-weight: 500;
  letter-spacing: 0;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  transition: background 0.15s, border-color 0.15s;
}

.testudo-btn-cancel:hover {
  background: var(--brand-hover);
  border-color: var(--brand-hover);
}

.testudo-btn-cancel:active {
  transform: scale(0.99);
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
  color: var(--text-dim);
  font-size: 13px;
  font-weight: 400;
  cursor: pointer;
  padding: 6px 12px;
  transition: color 0.15s, background 0.15s;
  border-radius: 6px;
}

.testudo-btn-link:hover {
  color: var(--text-muted);
  background: var(--surface-raised);
}

.testudo-btn-danger {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  background: transparent;
  border: 1px solid var(--danger-border);
  color: var(--danger);
  font-family: var(--font-sans);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  padding: 12px 18px;
  border-radius: 10px;
  transition: background 0.15s, border-color 0.15s, color 0.15s;
}

.testudo-btn-danger:hover {
  background: var(--surface-raised);
  border-color: var(--danger);
  color: var(--danger);
}

.testudo-btn-danger .testudo-material-icon {
  font-size: 14px;
  transition: transform 0.15s;
}

.testudo-btn-danger:hover .testudo-material-icon {
  transform: translateX(2px);
}

.testudo-btn-trust {
  background: transparent;
  border: 1px solid var(--border-strong);
  color: var(--text-muted);
  font-family: var(--font-sans);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  padding: 10px 14px;
  border-radius: 10px;
  transition: background 0.15s, color 0.15s, border-color 0.15s;
}

.testudo-btn-trust:hover {
  background: var(--surface-raised);
  color: var(--text-secondary);
  border-color: var(--text-muted);
}

/* ── eth_sign Confirmation ── */

.testudo-confirm-section,
.testudo-eth-sign-confirm {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.testudo-confirm-label {
  font-family: var(--font-sans);
  font-size: 11px;
  color: var(--text-dim);
  font-weight: 500;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.testudo-confirm-input,
.testudo-eth-sign-input {
  width: 100%;
  background: var(--surface-raised);
  border: 1px solid var(--danger-border);
  border-radius: 10px;
  padding: 11px 14px;
  font-size: 13px;
  font-family: var(--font-sans);
  color: var(--text);
  outline: none;
  transition: border-color 0.15s, box-shadow 0.15s;
  box-sizing: border-box;
}

.testudo-confirm-input:focus,
.testudo-eth-sign-input:focus {
  border-color: var(--danger);
  box-shadow: 0 0 0 2px rgba(220, 38, 38, 0.15);
}

.testudo-confirm-input::placeholder,
.testudo-eth-sign-input::placeholder {
  color: var(--text-dim);
}

.testudo-btn-danger-confirm {
  width: 100%;
  background: transparent;
  color: var(--text-dim);
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
  padding: 12px 18px;
  font-family: var(--font-sans);
  font-size: 13px;
  font-weight: 500;
  letter-spacing: 0;
  cursor: not-allowed;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  transition: background 0.15s, border-color 0.15s, color 0.15s;
}

.testudo-btn-danger-confirm.enabled {
  background: transparent;
  color: var(--danger);
  border-color: var(--danger-border);
  cursor: pointer;
}

.testudo-btn-danger-confirm.enabled:hover {
  background: var(--surface-raised);
  border-color: var(--danger);
}

/* ── Loading ── */

.testudo-loading-state {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.testudo-spin {
  animation: testudo-spin 1.5s linear infinite;
}

.testudo-loading-icon {
  background: var(--surface-raised);
  border-color: var(--border-strong);
  color: var(--text-muted);
}

.testudo-loading-bar-container {
  margin: 12px 24px;
  height: 2px;
  border-radius: 1px;
  background: var(--border-subtle);
  overflow: hidden;
}

.testudo-loading-bar {
  height: 100%;
  width: 50%;
  border-radius: 1px;
  background: linear-gradient(90deg, transparent, var(--brand), transparent);
  animation: testudo-loading-slide 1.4s ease-in-out infinite;
}

/* ── Toasts (shared) ── */

.testudo-toast,
.testudo-toast-info,
.testudo-toast-unknown {
  position: fixed;
  bottom: 16px;
  right: 16px;
  background: var(--surface);
  border-radius: 12px;
  padding: 14px 16px;
  color: var(--text-secondary);
  font-family: var(--font-sans);
  z-index: 999998;
  max-width: 360px;
  box-shadow: 0 12px 32px -4px rgba(0, 0, 0, 0.6);
  animation: testudo-slide-in 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  display: flex;
  gap: 10px;
  align-items: flex-start;
  -webkit-font-smoothing: antialiased;
  border: 1px solid var(--border-strong);
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
  letter-spacing: -0.005em;
}

.testudo-toast-text,
.testudo-toast-unknown-text {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 4px;
  line-height: 1.55;
}

.testudo-toast-dismiss,
.testudo-toast-unknown-dismiss {
  background: none;
  border: none;
  color: var(--text-dim);
  cursor: pointer;
  font-size: 11px;
  margin-top: 6px;
  padding: 4px 8px;
  border-radius: 6px;
  transition: background 0.15s, color 0.15s;
  font-weight: 500;
}

.testudo-toast-dismiss:hover,
.testudo-toast-unknown-dismiss:hover {
  background: var(--surface-raised);
  color: var(--text-secondary);
}

/* ── Info Toast (specifics) ── */

.testudo-toast,
.testudo-toast-info {
  border: 1px solid rgba(245, 158, 11, 0.3);
}

.testudo-toast .testudo-toast-icon,
.testudo-toast-info .testudo-toast-icon {
  color: var(--warn);
}

.testudo-toast .testudo-toast-title,
.testudo-toast-info .testudo-toast-title {
  color: var(--warn);
}

.testudo-toast-title .testudo-toast-icon-inline {
  font-family: 'Material Symbols Outlined';
  font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
  font-size: 14px;
}

/* ── Unknown Toast (specifics) ── */

.testudo-toast-unknown {
  border: 1px solid var(--border-strong);
}

.testudo-toast-unknown-icon {
  color: var(--text-dim);
}

.testudo-toast-unknown-title {
  color: var(--text-muted);
}

.testudo-toast-unknown-address {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-dim);
  margin-top: 5px;
}

/* ── Focus States (keyboard navigation) ── */

.testudo-btn:focus-visible,
.testudo-btn-cancel:focus-visible,
.testudo-btn-danger:focus-visible,
.testudo-btn-danger-confirm:focus-visible,
.testudo-btn-trust:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
}

.testudo-btn-link:focus-visible,
.testudo-copy-btn:focus-visible,
.testudo-toast-dismiss:focus-visible,
.testudo-toast-unknown-dismiss:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 1px;
  border-radius: 4px;
}

.testudo-confirm-input:focus-visible,
.testudo-eth-sign-input:focus-visible {
  outline: none;
  border-color: var(--danger);
  box-shadow: 0 0 0 2px rgba(220, 38, 38, 0.15);
}

/* ── Utility Classes ── */

.testudo-text-danger {
  color: var(--danger);
}

/* ── Reduced Motion ── */

@media (prefers-reduced-motion: reduce) {
  #testudo-warning-overlay,
  #testudo-warning-overlay *,
  #testudo-warning-overlay *::before,
  #testudo-warning-overlay *::after,
  .testudo-toast,
  .testudo-toast-info,
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
