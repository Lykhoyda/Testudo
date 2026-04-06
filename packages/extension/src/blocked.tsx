import '@preact/signals';
import { render } from 'preact';
import { BlockScreen } from './components/blocked/BlockScreen';

render(<BlockScreen />, document.getElementById('app')!);
