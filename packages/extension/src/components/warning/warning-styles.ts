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
  0% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0.4); }
  70% { box-shadow: 0 0 0 10px rgba(220, 38, 38, 0); }
  100% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0); }
}

@keyframes testudo-pulse-ring-amber {
  0% { box-shadow: 0 0 0 0 rgba(217, 119, 6, 0.3); }
  70% { box-shadow: 0 0 0 10px rgba(217, 119, 6, 0); }
  100% { box-shadow: 0 0 0 0 rgba(217, 119, 6, 0); }
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
  background: rgba(26, 26, 46, 0.85);
  backdrop-filter: blur(8px) saturate(1.2);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 999999;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  animation: testudo-fade-in 0.25s ease;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

.testudo-modal {
  background: #1a1a2e;
  border-radius: 12px;
  border: 1px solid rgba(220, 38, 38, 0.15);
  max-width: 440px;
  width: 92%;
  max-height: 90vh;
  color: #e5e7eb;
  box-shadow:
    0 0 0 1px rgba(220, 38, 38, 0.06),
    0 24px 48px -8px rgba(0, 0, 0, 0.7),
    0 0 80px -20px rgba(220, 38, 38, 0.08);
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
  background: linear-gradient(90deg, transparent 0%, #dc2626 30%, #ef4444 50%, #dc2626 70%, transparent 100%);
  opacity: 0.8;
}

.testudo-modal::after {
  content: '';
  position: absolute;
  top: 2px;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(220, 38, 38, 0.3), transparent);
  overflow: hidden;
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
  width: 56px;
  height: 56px;
  border-radius: 14px;
  background: rgba(220, 38, 38, 0.08);
  border: 1px solid rgba(220, 38, 38, 0.2);
  color: #ef4444;
  animation: testudo-pulse-ring 2s ease-in-out infinite;
}

.testudo-header-icon .testudo-material-icon {
  font-size: 28px;
}

.testudo-header-text {
  text-align: center;
}

.testudo-title {
  font-size: 18px;
  font-weight: 700;
  color: #ffffff;
  margin: 0 0 6px 0;
  letter-spacing: -0.025em;
  line-height: 1.3;
}

.testudo-subtitle {
  font-size: 13px;
  color: #9ca3af;
  margin: 0;
  line-height: 1.5;
  max-width: 340px;
}

.testudo-subtitle strong {
  color: #e5e7eb;
  font-weight: 600;
}

/* ── Alert Box ── */

.testudo-alert {
  margin: 4px 16px 0;
  position: relative;
  overflow: hidden;
  border-radius: 8px;
  border: 1px solid rgba(220, 38, 38, 0.25);
  background: rgba(220, 38, 38, 0.04);
  padding: 14px 16px;
}

.testudo-alert::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(220, 38, 38, 0.4), transparent);
}

.testudo-alert-header {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #ef4444;
  position: relative;
}

.testudo-alert-header .testudo-material-icon {
  font-size: 16px;
}

.testudo-alert-title {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.testudo-alert-medium {
  border-color: rgba(217, 119, 6, 0.25);
  background: rgba(217, 119, 6, 0.04);
}

.testudo-alert-medium::before {
  background: linear-gradient(90deg, transparent, rgba(217, 119, 6, 0.4), transparent);
}

.testudo-alert-medium .testudo-alert-header {
  color: #d97706;
}

.testudo-alert-description {
  color: #9ca3af;
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
  color: #9ca3af;
  line-height: 1.6;
  margin-bottom: 8px;
  padding: 0 4px;
}

.testudo-address-box {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #242442;
  border-radius: 6px;
  padding: 10px 14px;
  border: 1px solid rgba(255, 255, 255, 0.05);
  transition: border-color 0.15s;
}

.testudo-address-box:hover {
  border-color: rgba(255, 255, 255, 0.08);
}

.testudo-address-label {
  font-size: 11px;
  font-weight: 600;
  color: #6b7280;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.testudo-address-value {
  display: flex;
  align-items: center;
  gap: 8px;
}

.testudo-address-text {
  font-family: 'Roboto Mono', ui-monospace, monospace;
  font-size: 13px;
  color: #e5e7eb;
  letter-spacing: 0.01em;
}

.testudo-copy-btn {
  background: none;
  border: none;
  color: #6b7280;
  cursor: pointer;
  padding: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: color 0.15s;
  border-radius: 4px;
}

.testudo-copy-btn:hover {
  color: #9ca3af;
  background: rgba(255, 255, 255, 0.06);
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
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: #6b7280;
  margin-bottom: 8px;
  padding: 0 2px;
}

.testudo-threat-item {
  display: flex;
  align-items: center;
  gap: 12px;
  background: #242442;
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
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: rgba(217, 119, 6, 0.08);
  color: #d97706;
  flex-shrink: 0;
}

.testudo-threat-icon .testudo-material-icon {
  font-size: 18px;
}

.testudo-threat-content {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.testudo-threat-name {
  font-size: 13px;
  font-weight: 600;
  color: #e5e7eb;
  line-height: 1.3;
}

.testudo-threat-desc {
  font-size: 11px;
  color: #6b7280;
  margin-top: 2px;
  line-height: 1.4;
}

/* ── Buttons ── */

.testudo-buttons {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 12px 16px 20px;
  background: #1a1a2e;
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
  background: rgba(255, 255, 255, 0.05);
}

.testudo-btn-cancel {
  width: 100%;
  background: linear-gradient(180deg, #16a34a 0%, #15803d 100%);
  color: white;
  border: none;
  border-radius: 8px;
  padding: 14px 20px;
  font-size: 14px;
  font-weight: 700;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  box-shadow:
    0 1px 2px rgba(0, 0, 0, 0.3),
    inset 0 1px 0 rgba(255, 255, 255, 0.1);
  transition: all 0.15s;
  letter-spacing: 0.01em;
}

.testudo-btn-cancel:hover {
  background: linear-gradient(180deg, #22c55e 0%, #16a34a 100%);
  box-shadow:
    0 2px 8px rgba(22, 163, 74, 0.25),
    inset 0 1px 0 rgba(255, 255, 255, 0.15);
}

.testudo-btn-cancel:active {
  transform: scale(0.985);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
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
  color: #6b7280;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  padding: 6px 12px;
  transition: color 0.15s;
  border-radius: 6px;
}

.testudo-btn-link:hover {
  color: #9ca3af;
  background: rgba(255, 255, 255, 0.05);
}

.testudo-btn-danger {
  display: flex;
  align-items: center;
  gap: 4px;
  background: none;
  border: none;
  color: #6b7280;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  padding: 6px 12px;
  transition: all 0.15s;
  border-radius: 6px;
}

.testudo-btn-danger:hover {
  color: #ef4444;
  background: rgba(220, 38, 38, 0.06);
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
  font-size: 12px;
  color: #6b7280;
  font-weight: 500;
}

.testudo-confirm-input {
  width: 100%;
  background: #242442;
  border: 1px solid rgba(220, 38, 38, 0.2);
  border-radius: 6px;
  padding: 10px 12px;
  font-size: 13px;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  color: #e5e7eb;
  outline: none;
  transition: border-color 0.15s;
  box-sizing: border-box;
}

.testudo-confirm-input:focus {
  border-color: rgba(220, 38, 38, 0.5);
  box-shadow: 0 0 0 2px rgba(220, 38, 38, 0.08);
}

.testudo-confirm-input::placeholder {
  color: rgba(100, 116, 139, 0.5);
}

.testudo-btn-danger-confirm {
  width: 100%;
  background: rgba(220, 38, 38, 0.06);
  color: rgba(220, 38, 38, 0.3);
  border: 1px solid rgba(220, 38, 38, 0.12);
  border-radius: 8px;
  padding: 12px 20px;
  font-size: 13px;
  font-weight: 600;
  cursor: not-allowed;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  transition: all 0.15s;
}

.testudo-btn-danger-confirm.enabled {
  background: rgba(220, 38, 38, 0.12);
  color: #ef4444;
  border-color: rgba(220, 38, 38, 0.3);
  cursor: pointer;
}

.testudo-btn-danger-confirm.enabled:hover {
  background: rgba(220, 38, 38, 0.2);
  border-color: rgba(220, 38, 38, 0.5);
}

/* ── Loading ── */

.testudo-spin {
  animation: testudo-spin 1.5s linear infinite;
}

.testudo-loading-icon {
  background: rgba(59, 130, 246, 0.06);
  border-color: rgba(59, 130, 246, 0.15);
  color: #3b82f6;
  animation: none;
}

.testudo-loading-bar-container {
  margin: 12px 16px;
  height: 2px;
  border-radius: 1px;
  background: rgba(59, 130, 246, 0.08);
  overflow: hidden;
}

.testudo-loading-bar {
  height: 100%;
  width: 50%;
  border-radius: 1px;
  background: linear-gradient(90deg, transparent, #3b82f6, transparent);
  animation: testudo-loading-slide 1.4s ease-in-out infinite;
}

/* ── Toasts (shared) ── */

.testudo-toast,
.testudo-toast-unknown {
  position: fixed;
  bottom: 16px;
  right: 16px;
  background: #1a1a2e;
  border-radius: 10px;
  padding: 14px 16px;
  color: #e5e7eb;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  z-index: 999998;
  max-width: 360px;
  box-shadow: 0 12px 32px -4px rgba(0, 0, 0, 0.5);
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
  color: #6b7280;
  margin-top: 4px;
  line-height: 1.5;
}

.testudo-toast-dismiss,
.testudo-toast-unknown-dismiss {
  background: none;
  border: none;
  color: #6b7280;
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
  background: rgba(255, 255, 255, 0.06);
  color: #9ca3af;
}

/* ── Info Toast (specifics) ── */

.testudo-toast {
  border: 1px solid rgba(217, 119, 6, 0.2);
  box-shadow:
    0 0 0 1px rgba(217, 119, 6, 0.06),
    0 12px 32px -4px rgba(0, 0, 0, 0.5);
}

.testudo-toast::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(217, 119, 6, 0.3), transparent);
}

.testudo-toast-icon {
  color: #d97706;
}

.testudo-toast-title {
  color: #d97706;
}

.testudo-toast-title .testudo-toast-icon-inline {
  font-family: 'Material Symbols Outlined';
  font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
  font-size: 14px;
}

/* ── Unknown Toast (specifics) ── */

.testudo-toast-unknown {
  border: 1px solid rgba(255, 255, 255, 0.08);
}

.testudo-toast-unknown-icon {
  color: #6b7280;
}

.testudo-toast-unknown-title {
  color: #9ca3af;
}

.testudo-toast-unknown-address {
  font-family: 'Roboto Mono', monospace;
  font-size: 11px;
  color: #6b7280;
  margin-top: 5px;
}

/* ── Focus States (keyboard navigation) ── */

.testudo-btn-cancel:focus-visible,
.testudo-btn-danger-confirm:focus-visible {
  outline: 2px solid #3b82f6;
  outline-offset: 2px;
}

.testudo-btn-link:focus-visible,
.testudo-btn-danger:focus-visible,
.testudo-copy-btn:focus-visible,
.testudo-toast-dismiss:focus-visible,
.testudo-toast-unknown-dismiss:focus-visible {
  outline: 2px solid #3b82f6;
  outline-offset: 1px;
  border-radius: 4px;
}

.testudo-confirm-input:focus-visible {
  outline: none;
  border-color: rgba(59, 130, 246, 0.6);
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.15);
}

/* ── Utility Classes ── */

.testudo-text-danger {
  color: #ef4444;
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
