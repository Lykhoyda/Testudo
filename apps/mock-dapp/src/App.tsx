import { useState } from 'react';
import {
	API_ONLY_MALICIOUS_ADDRESS,
	CDN_SAFE_ADDRESS,
	createSeaportOrderTypedData,
	createTypedDataCleanAddresses,
	createTypedDataWithMaliciousAddress,
	MALICIOUS_ADDRESS,
	SAFE_ADDRESS,
	sendApproval,
	sendApprovalRevocation,
	sendIncreaseAllowance,
	sendSetApprovalForAll,
	sendTransaction,
	signDelegation,
	signEthMessage,
	signGenericTypedData,
	signPermit,
	signPermit2,
	signPermitTransferFrom,
	signPersonalMessage,
} from './mock-provider';
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

	const handleSignCdnSafe = async () => {
		setResult({ status: 'loading', message: 'Requesting signature for CDN-safe delegation...' });

		try {
			const signature = await signDelegation(CDN_SAFE_ADDRESS);
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
				<img src="/favicon.png" alt="Testudo" className="header-icon" />
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

					<button
						type="button"
						id="sign-cdn-safe"
						className="btn btn-success"
						onClick={handleSignCdnSafe}
					>
						<span className="btn-icon">✓</span>
						Sign CDN-Safe Delegation
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
					<div className="address-item">
						<span className="address-label success">CDN Safe:</span>
						<code>{CDN_SAFE_ADDRESS}</code>
					</div>
				</div>
			</section>

			<section className="card">
				<h2>Transaction Tests</h2>
				<p className="description">
					Test eth_sendTransaction interception. Testudo checks the recipient address against the
					threat database.
				</p>

				<div className="button-group">
					<button
						type="button"
						id="send-malicious"
						className="btn btn-danger"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Sending transaction to MALICIOUS address...',
							});
							try {
								const txHash = await sendTransaction(MALICIOUS_ADDRESS);
								setResult({
									status: 'success',
									message: `Transaction sent (user proceeded):\n${txHash}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						Send to Malicious Address
					</button>

					<button
						type="button"
						id="send-safe"
						className="btn btn-success"
						onClick={async () => {
							setResult({ status: 'loading', message: 'Sending transaction to SAFE address...' });
							try {
								const txHash = await sendTransaction(SAFE_ADDRESS);
								setResult({ status: 'success', message: `Transaction sent:\n${txHash}` });
							} catch (error) {
								setResult({
									status: 'error',
									message: `Error:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">✓</span>
						Send to Safe Address
					</button>

					<button
						type="button"
						id="send-api-only-malicious"
						className="btn btn-warning"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Sending transaction to API-only malicious address...',
							});
							try {
								const txHash = await sendTransaction(API_ONLY_MALICIOUS_ADDRESS);
								setResult({
									status: 'success',
									message: `Transaction sent (API-only threat):\n${txHash}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						Send to API-Only Malicious
					</button>
				</div>
			</section>

			<section className="card">
				<h2>Token Approval Tests</h2>
				<p className="description">
					Test ERC20 approve() and increaseAllowance() interception. Testudo parses calldata to
					check the spender address against the threat database and warns about unlimited approvals.
				</p>

				<div className="button-group">
					<button
						type="button"
						id="approve-malicious-unlimited"
						className="btn btn-danger"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Sending approve() with MALICIOUS spender (unlimited)...',
							});
							try {
								const txHash = await sendApproval(
									'0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
									MALICIOUS_ADDRESS,
									true,
								);
								setResult({
									status: 'success',
									message: `Approval sent (user proceeded):\n${txHash}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						Approve Malicious (Unlimited)
					</button>

					<button
						type="button"
						id="approve-safe-limited"
						className="btn btn-success"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Sending approve() with SAFE spender (limited)...',
							});
							try {
								const txHash = await sendApproval(
									'0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
									SAFE_ADDRESS,
									false,
								);
								setResult({
									status: 'success',
									message: `Approval sent:\n${txHash}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Error:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">✓</span>
						Approve Safe (Limited)
					</button>

					<button
						type="button"
						id="increase-allowance-malicious"
						className="btn btn-danger"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Sending increaseAllowance() with MALICIOUS spender...',
							});
							try {
								const txHash = await sendIncreaseAllowance(
									'0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
									MALICIOUS_ADDRESS,
									true,
								);
								setResult({
									status: 'success',
									message: `increaseAllowance sent (user proceeded):\n${txHash}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						increaseAllowance (Malicious)
					</button>

					<button
						type="button"
						id="approve-unknown-unlimited"
						className="btn btn-warning"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Sending approve() with UNKNOWN spender (unlimited)...',
							});
							try {
								const txHash = await sendApproval(
									'0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
									'0x2222222222222222222222222222222222222222',
									true,
								);
								setResult({
									status: 'success',
									message: `Approval sent (user proceeded):\n${txHash}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						Approve Unknown (Unlimited)
					</button>

					<button
						type="button"
						id="revoke-approval"
						className="btn btn-success"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Sending approve() with amount=0 (revocation)...',
							});
							try {
								const txHash = await sendApprovalRevocation(
									'0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
									MALICIOUS_ADDRESS,
								);
								setResult({
									status: 'success',
									message: `Revocation sent (silent pass):\n${txHash}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Error:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">✓</span>
						Revoke Approval (amount=0)
					</button>
				</div>
			</section>

			<section className="card">
				<h2>NFT setApprovalForAll Tests</h2>
				<p className="description">
					Test ERC721/ERC1155 setApprovalForAll() interception. Testudo checks the operator address
					against the threat database and known marketplaces.
				</p>

				<div className="button-group">
					<button
						type="button"
						id="nft-approval-malicious"
						className="btn btn-danger"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Sending setApprovalForAll() with MALICIOUS operator...',
							});
							try {
								const txHash = await sendSetApprovalForAll(
									'0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d',
									MALICIOUS_ADDRESS,
									true,
								);
								setResult({
									status: 'success',
									message: `setApprovalForAll sent (user proceeded):\n${txHash}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						setApprovalForAll (Malicious Operator)
					</button>

					<button
						type="button"
						id="nft-approval-opensea"
						className="btn btn-success"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Sending setApprovalForAll() with OpenSea Seaport...',
							});
							try {
								const txHash = await sendSetApprovalForAll(
									'0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d',
									'0x1e0049783f008a0085193e00003d00cd54003c71',
									true,
								);
								setResult({
									status: 'success',
									message: `setApprovalForAll sent (OpenSea trusted):\n${txHash}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Error:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">✓</span>
						setApprovalForAll (OpenSea)
					</button>

					<button
						type="button"
						id="nft-approval-unknown"
						className="btn btn-warning"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Sending setApprovalForAll() with UNKNOWN operator...',
							});
							try {
								const txHash = await sendSetApprovalForAll(
									'0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d',
									'0x3333333333333333333333333333333333333333',
									true,
								);
								setResult({
									status: 'success',
									message: `setApprovalForAll sent (user proceeded):\n${txHash}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						setApprovalForAll (Unknown Operator)
					</button>

					<button
						type="button"
						id="nft-approval-revoke"
						className="btn btn-success"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Sending setApprovalForAll(approved=false) revocation...',
							});
							try {
								const txHash = await sendSetApprovalForAll(
									'0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d',
									MALICIOUS_ADDRESS,
									false,
								);
								setResult({
									status: 'success',
									message: `Revocation sent (silent pass):\n${txHash}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Error:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">✓</span>
						Revoke setApprovalForAll
					</button>
				</div>
			</section>

			<section className="card">
				<h2>Permit Signature Tests</h2>
				<p className="description">
					Test Permit and Permit2 signature interception. Testudo checks the spender address against
					the threat database and warns about unlimited approvals.
				</p>

				<div className="button-group">
					<button
						type="button"
						id="sign-permit-malicious"
						className="btn btn-danger"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Requesting Permit signature with MALICIOUS spender...',
							});
							try {
								const sig = await signPermit(MALICIOUS_ADDRESS);
								setResult({
									status: 'success',
									message: `Permit signed (user proceeded):\n${sig}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						Sign Permit (Malicious Spender)
					</button>

					<button
						type="button"
						id="sign-permit2-safe"
						className="btn btn-success"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Requesting Permit2 signature with SAFE spender...',
							});
							try {
								const sig = await signPermit2(SAFE_ADDRESS);
								setResult({
									status: 'success',
									message: `Permit2 signed:\n${sig}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Error:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">✓</span>
						Sign Permit2 (Safe Spender)
					</button>

					<button
						type="button"
						id="sign-permit-transfer-malicious"
						className="btn btn-danger"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Requesting PermitTransferFrom with MALICIOUS spender...',
							});
							try {
								const sig = await signPermitTransferFrom(MALICIOUS_ADDRESS);
								setResult({
									status: 'success',
									message: `PermitTransferFrom signed (user proceeded):\n${sig}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						Sign PermitTransferFrom (Malicious)
					</button>
				</div>
			</section>

			<section className="card">
				<h2>Blind Signature Tests</h2>
				<p className="description">
					Test personal_sign and eth_sign interception. These are "blind signatures" where users
					sign arbitrary data without structured information about what they're authorizing.
				</p>

				<div className="button-group">
					<button
						type="button"
						id="personal-sign-hex"
						className="btn btn-warning"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Requesting personal_sign with hex message...',
							});
							try {
								const sig = await signPersonalMessage('0x48656c6c6f20576f726c64');
								setResult({
									status: 'success',
									message: `personal_sign completed (user proceeded):\n${sig}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						personal_sign (Hex Message)
					</button>

					<button
						type="button"
						id="personal-sign-text"
						className="btn btn-warning"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Requesting personal_sign with text message...',
							});
							try {
								const sig = await signPersonalMessage('Hello, please sign this message');
								setResult({
									status: 'success',
									message: `personal_sign completed (user proceeded):\n${sig}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						personal_sign (Text Message)
					</button>

					<button
						type="button"
						id="eth-sign"
						className="btn btn-danger"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Requesting eth_sign (legacy - dangerous)...',
							});
							try {
								const sig = await signEthMessage('0xdeadbeef');
								setResult({
									status: 'success',
									message: `eth_sign completed (user proceeded):\n${sig}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						eth_sign (Legacy - Dangerous)
					</button>
				</div>
			</section>

			<section className="card">
				<h2>Phishing Pattern Tests</h2>
				<p className="description">
					Test phishing pattern detection in personal_sign messages. Messages containing airdrop
					scams, verification tricks, or urgency language are escalated to HIGH severity.
				</p>

				<div className="button-group">
					<button
						type="button"
						id="personal-sign-login"
						className="btn btn-success"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Requesting personal_sign with login message...',
							});
							try {
								const sig = await signPersonalMessage('Login to OpenSea');
								setResult({
									status: 'success',
									message: `personal_sign completed:\n${sig}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">✓</span>
						personal_sign &quot;Login to OpenSea&quot;
					</button>

					<button
						type="button"
						id="personal-sign-airdrop"
						className="btn btn-danger"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Requesting personal_sign with phishing message...',
							});
							try {
								const sig = await signPersonalMessage(
									'Claim your free airdrop reward now! Act now, limited time offer!',
								);
								setResult({
									status: 'success',
									message: `personal_sign completed (user proceeded):\n${sig}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						personal_sign Phishing (Airdrop)
					</button>
				</div>
			</section>

			<section className="card">
				<h2>Typed Data Address Scanning Tests</h2>
				<p className="description">
					Test recursive address extraction from eth_signTypedData_v4. All addresses found in the
					typed data are checked against the threat database.
				</p>

				<div className="button-group">
					<button
						type="button"
						id="typed-data-malicious-recipient"
						className="btn btn-danger"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Signing typed data with malicious recipient...',
							});
							try {
								const typedData = createTypedDataWithMaliciousAddress();
								const sig = await signGenericTypedData(typedData);
								setResult({
									status: 'success',
									message: `Typed data signed (user proceeded):\n${sig}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Blocked:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">⚠️</span>
						Transfer to Malicious Address
					</button>

					<button
						type="button"
						id="typed-data-clean"
						className="btn btn-success"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Signing typed data with clean addresses...',
							});
							try {
								const typedData = createTypedDataCleanAddresses();
								const sig = await signGenericTypedData(typedData);
								setResult({
									status: 'success',
									message: `Typed data signed:\n${sig}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Error:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">✓</span>
						Transfer to Safe Address
					</button>

					<button
						type="button"
						id="typed-data-seaport"
						className="btn btn-success"
						onClick={async () => {
							setResult({
								status: 'loading',
								message: 'Signing Seaport order with known addresses...',
							});
							try {
								const typedData = createSeaportOrderTypedData();
								const sig = await signGenericTypedData(typedData);
								setResult({
									status: 'success',
									message: `Seaport order signed:\n${sig}`,
								});
							} catch (error) {
								setResult({
									status: 'error',
									message: `Error:\n${error instanceof Error ? error.message : 'Unknown error'}`,
								});
							}
						}}
					>
						<span className="btn-icon">✓</span>
						Seaport Order (Clean)
					</button>
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
