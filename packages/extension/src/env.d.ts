declare namespace NodeJS {
	interface ProcessEnv {
		TESTUDO_API_URL: string;
	}
}

declare const process: {
	env: {
		TESTUDO_API_URL: string;
	};
};
