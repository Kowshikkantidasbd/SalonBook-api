
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';


export const BACKEND_DIR = path.dirname(fileURLToPath(import.meta.url));

function isPlaceholderEnvValue(value) {
  if (typeof value !== 'string') return true;
  const trimmed = value.trim();
  return !trimmed || /^MY_[A-Z0-9_]+$/.test(trimmed);
}



for (const envPath of [
  path.resolve(BACKEND_DIR, '../.env.local'),
  path.resolve(BACKEND_DIR, '../.env'),
  path.resolve(BACKEND_DIR, '.env'),
]) {
  if (fs.existsSync(envPath)) {
    const parsed = dotenv.parse(fs.readFileSync(envPath));
    for (const [key, value] of Object.entries(parsed)) {
      const current = process.env[key];
      if (current === undefined || isPlaceholderEnvValue(current)) {
        if (!isPlaceholderEnvValue(value) || current === undefined) {
          process.env[key] = value;
        }
      }
    }
  }
}


const EPHEMERAL_JWT_SECRET = crypto.randomBytes(32).toString('hex');
const EPHEMERAL_WEBHOOK_SECRET = `whsec_${crypto.randomBytes(24).toString('hex')}`;

export const isServerless = Boolean(
  process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME
);

export const UPLOADS_DIR = isServerless
  ? path.join('/tmp', 'salonbook-uploads')
  : path.resolve(BACKEND_DIR, 'uploads');

export function getPort() {
  return Number(process.env.PORT) || 5000;
}

let warnedMissingJwtSecret = false;

export function getJwtSecret() {
  const configured = process.env.JWT_SECRET?.trim() || '';
  if (configured && !isPlaceholderEnvValue(configured)) {
    return configured;
  }
  if (isServerless && !warnedMissingJwtSecret) {
    warnedMissingJwtSecret = true;
    console.warn(
      '[SalonBook] JWT_SECRET is not set in environment variables. Set a strong JWT_SECRET in Vercel Project Settings so sessions persist across serverless instances.'
    );
  }
  return EPHEMERAL_JWT_SECRET;
}

export function getMongoUri() {
  const candidates = [
    process.env.MONGODB_URI,
    process.env.MONGO_URI,
    process.env.DATABASE_URL,
  ];
  for (const raw of candidates) {
    const uri = raw?.trim() || '';
    if (!uri || uri === 'MY_MONGODB_URI') continue;
    if (/^mongodb(\+srv)?:\/\//i.test(uri)) {
      return uri;
    }
  }
  return '';
}

export function resolveMongoDbName(mongoUri, explicitDbName = process.env.MONGODB_DB_NAME) {
  const override = explicitDbName?.trim();
  if (override) return override;
  if (!mongoUri || typeof mongoUri !== 'string') return 'salonbook';

  const trimmed = mongoUri.trim();
  const schemeEnd = trimmed.indexOf('://');
  if (schemeEnd === -1) return 'salonbook';

  const afterScheme = trimmed.slice(schemeEnd + 3);
  const queryStart = afterScheme.indexOf('?');
  const authorityAndPath = queryStart === -1 ? afterScheme : afterScheme.slice(0, queryStart);
  const firstSlash = authorityAndPath.indexOf('/');
  if (firstSlash === -1) return 'salonbook';

  const dbPath = authorityAndPath.slice(firstSlash + 1).replace(/^\/+|\/+$/g, '').trim();
  if (!dbPath) return 'salonbook';

  return undefined;
}

export function sanitizeMongoError(err) {
  const raw = err instanceof Error ? err.message : String(err || 'Unknown MongoDB error');
  return raw.replace(/mongodb(\+srv)?:\/\/[^\s@]+@/gi, 'mongodb$1://***:***@').slice(0, 220);
}

export function getStripeSecretKey() {
  const key = process.env.STRIPE_SECRET_KEY?.trim() || '';
  if (!key || key === 'MY_STRIPE_SECRET_KEY') return '';
  return key;
}

export function getStripeWebhookSecret() {
  const secret = process.env.STRIPE_WEBHOOK_SECRET?.trim() || '';
  if (!secret || secret === 'MY_STRIPE_WEBHOOK_SECRET') {
    return EPHEMERAL_WEBHOOK_SECRET;
  }
  return secret;
}

export function getImgbbApiKey() {
  const key = process.env.IMGBB_API_KEY?.trim() || '';
  if (!key || key === 'MY_IMGBB_API_KEY') return '';
  return key;
}

export function getGoogleClientId() {
  const envClientId = process.env.GOOGLE_CLIENT_ID?.trim() || '';
  if (!envClientId || envClientId === 'MY_GOOGLE_CLIENT_ID') return '';
  return envClientId;
}

export function getGoogleClientSecret() {
  const envSecret = process.env.GOOGLE_CLIENT_SECRET?.trim() || '';
  if (!envSecret || envSecret === 'MY_GOOGLE_CLIENT_SECRET') return '';
  return envSecret;
}

export function isGoogleSocialAuthEnabled() {
  return Boolean(getGoogleClientId());
}

function toHttpsOrigin(hostOrUrl) {
  const trimmed = String(hostOrUrl || '').trim().replace(/\/$/, '');
  if (!trimmed) return '';
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return trimmed;
  }
  return `https://${trimmed}`;
}
