export const WARNING_STYLES = `
#testudo-warning-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.8);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 999999;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  animation: testudo-fade-in 0.3s ease;
}

@keyframes testudo-fade-in {
  from { opacity: 0; }
  to { opacity: 1; }
}

@keyframes testudo-zoom-in {
  from { opacity: 0; transform: scale(0.95); }
  to { opacity: 1; transform: scale(1); }
}

.testudo-modal {
  background: #1a232e;
  border-radius: 16px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  max-width: 480px;
  width: 90%;
  max-height: 90vh;
  color: white;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
  overflow: hidden;
  animation: testudo-zoom-in 0.3s ease;
  display: flex;
  flex-direction: column;
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

.testudo-header {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 32px 24px 16px;
  gap: 16px;
  flex-shrink: 0;
}

.testudo-header-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 80px;
  height: 80px;
  border-radius: 50%;
  background: rgba(231, 76, 60, 0.1);
  color: #e74c3c;
}

.testudo-header-icon .testudo-material-icon {
  font-size: 48px;
}

.testudo-header-text {
  text-align: center;
}

.testudo-title {
  font-size: 24px;
  font-weight: bold;
  color: #fff;
  margin: 0 0 8px 0;
  letter-spacing: -0.02em;
}

.testudo-subtitle {
  font-size: 14px;
  color: #97adc4;
  margin: 0;
  line-height: 1.5;
}

.testudo-subtitle strong {
  color: #fff;
  font-weight: 500;
}

.testudo-alert {
  margin: 0 24px;
  position: relative;
  overflow: hidden;
  border-radius: 8px;
  border: 1px solid rgba(231, 76, 60, 0.4);
  background: rgba(231, 76, 60, 0.1);
  padding: 20px;
}

.testudo-alert::before {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, rgba(231, 76, 60, 0.1) 0%, transparent 100%);
  pointer-events: none;
}

.testudo-alert-header {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #e74c3c;
  position: relative;
  z-index: 1;
}

.testudo-alert-header .testudo-material-icon {
  font-size: 20px;
}

.testudo-alert-title {
  font-size: 14px;
  font-weight: 700;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.testudo-alert-medium {
  border-color: rgba(245, 158, 11, 0.4);
  background: rgba(245, 158, 11, 0.1);
}

.testudo-alert-medium::before {
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, transparent 100%);
}

.testudo-alert-medium .testudo-alert-header {
  color: #f59e0b;
}

.testudo-alert-description {
  color: rgba(255, 255, 255, 0.9);
  font-size: 14px;
  font-weight: 500;
  line-height: 1.6;
  margin-top: 8px;
  position: relative;
  z-index: 1;
}

.testudo-threats {
  padding: 16px 24px;
  margin-top: 16px;
  overflow-y: auto;
  max-height: 280px;
  flex-shrink: 1;
}

.testudo-threats-title {
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: rgba(255, 255, 255, 0.7);
  margin-bottom: 12px;
  padding: 0 4px;
}

.testudo-threat-item {
  display: flex;
  align-items: center;
  gap: 16px;
  background: rgba(18, 26, 33, 0.5);
  border-radius: 8px;
  padding: 12px;
  border: 1px solid rgba(255, 255, 255, 0.05);
  margin-bottom: 8px;
}

.testudo-threat-item:last-child {
  margin-bottom: 0;
}

.testudo-threat-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  border-radius: 8px;
  background: rgba(245, 158, 11, 0.1);
  color: #f59e0b;
  flex-shrink: 0;
}

.testudo-threat-icon .testudo-material-icon {
  font-size: 24px;
}

.testudo-threat-content {
  display: flex;
  flex-direction: column;
}

.testudo-threat-name {
  font-size: 14px;
  font-weight: 500;
  color: #fff;
  line-height: 1.4;
}

.testudo-threat-desc {
  font-size: 12px;
  color: #97adc4;
  margin-top: 2px;
}

.testudo-intent-action {
  font-size: 14px;
  color: rgba(255, 255, 255, 0.9);
  line-height: 1.6;
  margin-bottom: 8px;
  padding: 0 12px;
}

.testudo-address-section {
  margin: 8px 24px;
}

.testudo-address-box {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #121a21;
  border-radius: 4px;
  padding: 8px 12px;
  border: 1px solid rgba(255, 255, 255, 0.05);
}

.testudo-address-label {
  font-size: 12px;
  font-weight: 500;
  color: #97adc4;
}

.testudo-address-value {
  display: flex;
  align-items: center;
  gap: 8px;
}

.testudo-address-text {
  font-family: 'Roboto Mono', ui-monospace, monospace;
  font-size: 14px;
  color: #fff;
  letter-spacing: 0.02em;
}

.testudo-copy-btn {
  background: none;
  border: none;
  color: #97adc4;
  cursor: pointer;
  padding: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: color 0.2s;
}

.testudo-copy-btn:hover {
  color: #fff;
}

.testudo-copy-btn .testudo-material-icon {
  font-size: 16px;
}

.testudo-buttons {
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 8px 24px 24px;
  background: #1a232e;
  flex-shrink: 0;
}

.testudo-btn-cancel {
  width: 100%;
  background: #27ae60;
  color: white;
  border: none;
  border-radius: 8px;
  padding: 16px 24px;
  font-size: 16px;
  font-weight: 700;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  box-shadow: 0 4px 14px rgba(39, 174, 96, 0.2);
  transition: all 0.2s;
}

.testudo-btn-cancel:hover {
  background: #229954;
}

.testudo-btn-cancel:active {
  transform: scale(0.98);
}

.testudo-btn-cancel .testudo-material-icon {
  font-size: 20px;
}

.testudo-secondary-actions {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 24px;
  padding-top: 8px;
}

.testudo-btn-link {
  background: none;
  border: none;
  color: #97adc4;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  padding: 8px;
  transition: color 0.2s;
  border-bottom: 1px solid transparent;
}

.testudo-btn-link:hover {
  color: #fff;
  border-bottom-color: rgba(255, 255, 255, 0.2);
}

.testudo-btn-danger {
  display: flex;
  align-items: center;
  gap: 4px;
  background: none;
  border: none;
  color: rgba(231, 76, 60, 0.7);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  padding: 8px;
  transition: color 0.2s;
}

.testudo-btn-danger:hover {
  color: #e74c3c;
}

.testudo-btn-danger .testudo-material-icon {
  font-size: 16px;
  transition: transform 0.2s;
}

.testudo-btn-danger:hover .testudo-material-icon {
  transform: translateX(2px);
}

.testudo-confirm-section {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.testudo-confirm-label {
  font-size: 13px;
  color: #97adc4;
  font-weight: 500;
}

.testudo-confirm-input {
  width: 100%;
  background: #121a21;
  border: 1px solid rgba(231, 76, 60, 0.3);
  border-radius: 6px;
  padding: 12px;
  font-size: 14px;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  color: #fff;
  outline: none;
  transition: border-color 0.2s;
  box-sizing: border-box;
}

.testudo-confirm-input:focus {
  border-color: rgba(231, 76, 60, 0.6);
}

.testudo-confirm-input::placeholder {
  color: rgba(151, 173, 196, 0.5);
}

.testudo-btn-danger-confirm {
  width: 100%;
  background: rgba(231, 76, 60, 0.15);
  color: rgba(231, 76, 60, 0.4);
  border: 1px solid rgba(231, 76, 60, 0.2);
  border-radius: 8px;
  padding: 14px 24px;
  font-size: 15px;
  font-weight: 600;
  cursor: not-allowed;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  transition: all 0.2s;
}

.testudo-btn-danger-confirm.enabled {
  background: rgba(231, 76, 60, 0.9);
  color: #fff;
  border-color: #e74c3c;
  cursor: pointer;
}

.testudo-btn-danger-confirm.enabled:hover {
  background: #e74c3c;
}

.testudo-toast {
  position: fixed;
  bottom: 20px;
  right: 20px;
  background: #1a232e;
  border: 1px solid rgba(245, 158, 11, 0.4);
  border-radius: 12px;
  padding: 16px 20px;
  color: white;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  z-index: 999998;
  max-width: 400px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
  animation: testudo-slide-in 0.3s ease;
  display: flex;
  gap: 12px;
  align-items: flex-start;
}

@keyframes testudo-slide-in {
  from { transform: translateX(100%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}

.testudo-toast-icon {
  font-family: 'Material Symbols Outlined';
  font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
  font-size: 24px;
  color: #f59e0b;
}

.testudo-toast-content {
  flex: 1;
}

.testudo-toast-title {
  font-weight: 600;
  color: #f59e0b;
  font-size: 14px;
  display: flex;
  align-items: center;
  gap: 6px;
}

.testudo-toast-title .testudo-toast-icon-inline {
  font-family: 'Material Symbols Outlined';
  font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
  font-size: 16px;
}

.testudo-toast-text {
  font-size: 13px;
  color: #97adc4;
  margin-top: 4px;
  line-height: 1.5;
}

.testudo-toast-dismiss {
  background: none;
  border: none;
  color: #97adc4;
  cursor: pointer;
  font-size: 12px;
  margin-top: 8px;
  padding: 4px 8px;
  border-radius: 4px;
  transition: background 0.2s, color 0.2s;
}

.testudo-toast-dismiss:hover {
  background: rgba(255, 255, 255, 0.1);
  color: #fff;
}

.testudo-toast-unknown {
  position: fixed;
  bottom: 20px;
  right: 20px;
  background: #1a232e;
  border: 1px solid rgba(148, 163, 184, 0.4);
  border-radius: 12px;
  padding: 16px 20px;
  color: white;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  z-index: 999998;
  max-width: 400px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
  animation: testudo-slide-in 0.3s ease;
  display: flex;
  gap: 12px;
  align-items: flex-start;
}

.testudo-toast-unknown-icon {
  font-family: 'Material Symbols Outlined';
  font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
  font-size: 24px;
  color: #94a3b8;
}

.testudo-toast-unknown-content {
  flex: 1;
}

.testudo-toast-unknown-title {
  font-weight: 600;
  color: #94a3b8;
  font-size: 14px;
  display: flex;
  align-items: center;
  gap: 6px;
}

.testudo-toast-unknown-text {
  font-size: 13px;
  color: #97adc4;
  margin-top: 4px;
  line-height: 1.5;
}

.testudo-toast-unknown-address {
  font-family: 'Roboto Mono', monospace;
  font-size: 12px;
  color: #64748b;
  margin-top: 6px;
}

.testudo-toast-unknown-dismiss {
  background: none;
  border: none;
  color: #97adc4;
  cursor: pointer;
  font-size: 12px;
  margin-top: 8px;
  padding: 4px 8px;
  border-radius: 4px;
  transition: background 0.2s, color 0.2s;
}

.testudo-toast-unknown-dismiss:hover {
  background: rgba(255, 255, 255, 0.1);
  color: #fff;
}
`;

export function injectWarningStyles(): void {
	if (document.getElementById('testudo-warning-styles')) return;
	const style = document.createElement('style');
	style.id = 'testudo-warning-styles';
	style.textContent = WARNING_STYLES;
	document.head.appendChild(style);
}
