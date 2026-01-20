import { useState } from 'react';
import { MALICIOUS_ADDRESS, SAFE_ADDRESS, signDelegation } from './mock-provider';
import './App.css';

type ResultStatus = 'idle' | 'loading' | 'success' | 'error';

interface Result {
	status: ResultStatus;
	message: string;
}

function App() {
	const [result, setResult] = useState<Result>({
		status: 'idle',
		message: 'Waiting for action...',
	});

	const handleSignMalicious = async () => {
		setResult({ status: 'loading', message: 'Requesting signature for MALICIOUS delegation...' });

		try {
			const signature = await signDelegation(MALICIOUS_ADDRESS);
			setResult({
				status: 'success',
				message: `Signature received (user proceeded):\n${signature}`,
			});
		} catch (error) {
			setResult({
				status: 'error',
				message: `Blocked/Rejected:\n${error instanceof Error ? error.message : 'Unknown error'}`,
			});
		}
	};

	const handleSignSafe = async () => {
		setResult({ status: 'loading', message: 'Requesting signature for SAFE delegation...' });

		try {
			const signature = await signDelegation(SAFE_ADDRESS);
			setResult({
				status: 'success',
				message: `Signature received:\n${signature}`,
			});
		} catch (error) {
			setResult({
				status: 'error',
				message: `Error:\n${error instanceof Error ? error.message : 'Unknown error'}`,
			});
		}
	};

	const handleSignCustom = async (address: string) => {
		if (!address.match(/^0x[a-fA-F0-9]{40}$/)) {
			setResult({ status: 'error', message: 'Invalid address format' });
			return;
		}

		setResult({ status: 'loading', message: `Requesting signature for ${address}...` });

		try {
			const signature = await signDelegation(address);
			setResult({
				status: 'success',
				message: `Signature received:\n${signature}`,
			});
		} catch (error) {
			setResult({
				status: 'error',
				message: `Blocked/Rejected:\n${error instanceof Error ? error.message : 'Unknown error'}`,
			});
		}
	};

	return (
		<div className="app">
			<header className="header">
				<div className="header-icon">🛡️</div>
				<div>
					<h1>Testudo Test dApp</h1>
					<p className="subtitle">Test EIP-7702 delegation detection</p>
				</div>
			</header>

			<section className="card">
				<h2>Provider Status</h2>
				<div className="status-badge success">
					<span className="status-dot" />
					<span id="provider-status">Ready</span>
				</div>
			</section>

			<section className="card">
				<h2>EIP-7702 Delegation Tests</h2>
				<p className="description">
					Click the buttons below to trigger EIP-7702 delegation signature requests. The Testudo
					extension will analyze the target contract and show warnings for dangerous delegations.
				</p>

				<div className="button-group">
					<button
						type="button"
						id="sign-malicious"
						className="btn btn-danger"
						onClick={handleSignMalicious}
					>
						<span className="btn-icon">⚠️</span>
						Sign Malicious Delegation
					</button>

					<button type="button" id="sign-safe" className="btn btn-success" onClick={handleSignSafe}>
						<span className="btn-icon">✓</span>
						Sign Safe Delegation
					</button>
				</div>

				<div className="addresses">
					<div className="address-item">
						<span className="address-label danger">Malicious:</span>
						<code>{MALICIOUS_ADDRESS}</code>
					</div>
					<div className="address-item">
						<span className="address-label success">Safe:</span>
						<code>{SAFE_ADDRESS}</code>
					</div>
				</div>
			</section>

			<section className="card">
				<h2>Custom Address Test</h2>
				<CustomAddressForm onSubmit={handleSignCustom} />
			</section>

			<section className="card">
				<h2>Result</h2>
				<div id="result" className={`result ${result.status}`}>
					{result.message}
				</div>
			</section>
		</div>
	);
}

function CustomAddressForm({ onSubmit }: { onSubmit: (address: string) => void }) {
	const [address, setAddress] = useState('');

	const handleSubmit = (e: React.FormEvent) => {
		e.preventDefault();
		if (address) {
			onSubmit(address);
		}
	};

	return (
		<form className="custom-form" onSubmit={handleSubmit}>
			<input
				type="text"
				value={address}
				onChange={(e) => setAddress(e.target.value)}
				placeholder="0x..."
				className="input"
			/>
			<button type="submit" className="btn btn-primary">
				Sign Custom
			</button>
		</form>
	);
}

export default App;
