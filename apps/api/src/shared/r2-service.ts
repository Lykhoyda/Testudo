import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';

let client: S3Client | null = null;

function getClient(): S3Client {
	if (client) return client;

	const accountId = process.env.R2_ACCOUNT_ID;
	const accessKeyId = process.env.R2_ACCESS_KEY_ID;
	const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;

	if (!accountId || !accessKeyId || !secretAccessKey) {
		throw new Error('R2 credentials not configured (R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY)');
	}

	client = new S3Client({
		region: 'auto',
		endpoint: `https://${accountId}.r2.cloudflarestorage.com`,
		credentials: { accessKeyId, secretAccessKey },
	});

	return client;
}

export async function uploadToR2(
	key: string,
	body: Buffer | string,
	contentType: string,
	cacheControl?: string,
): Promise<string> {
	const bucket = process.env.R2_BUCKET_NAME ?? 'testudo-cdn';
	const publicDomain = process.env.R2_PUBLIC_DOMAIN ?? 'cdn.testudo.security';

	const maxAge = cacheControl ?? (key.includes('revocation') ? 'public, max-age=3600' : 'public, max-age=86400');

	await getClient().send(
		new PutObjectCommand({
			Bucket: bucket,
			Key: key,
			Body: typeof body === 'string' ? Buffer.from(body) : body,
			ContentType: contentType,
			CacheControl: maxAge,
		}),
	);

	const base = publicDomain.startsWith('http') ? publicDomain : `https://${publicDomain}`;
	return `${base}/${key}`;
}
