import '@preact/signals';
import { render } from 'preact';
import { BlockScreen } from './components/blocked/BlockScreen';

const root = document.getElementById('app');
if (root) render(<BlockScreen />, root);
