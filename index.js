
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