import '@preact/signals';
import { render } from 'preact';
import { PopupApp } from './components/popup/PopupApp';

const app = document.getElementById('app');
if (app) {
	render(<PopupApp />, app);
}
