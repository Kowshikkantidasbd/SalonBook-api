
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';


export const BACKEND_DIR = path.dirname(fileURLToPath(import.meta.url));

function isPlaceholderEnvValue(value) {
  if (typeof value !== 'string') return true;
  const trimmed = value.trim();
  return !trimmed || /^MY_[A-Z0-9_]+$/.test(trimmed);
}