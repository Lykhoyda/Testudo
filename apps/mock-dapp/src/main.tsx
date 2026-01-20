import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './index.css';
import { initMockProvider } from './mock-provider';

// Initialize the mock ethereum provider
initMockProvider();

const rootElement = document.getElementById('root');
if (!rootElement) throw new Error('Root element not found');

createRoot(rootElement).render(
	<StrictMode>
		<App />
	</StrictMode>,
);
