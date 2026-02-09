import '@preact/signals';
import { render } from 'preact';
import { OptionsApp } from './components/options/OptionsApp';

const app = document.getElementById('app');
if (app) {
	render(<OptionsApp />, app);
}
