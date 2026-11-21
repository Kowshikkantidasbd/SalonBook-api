
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import zlib from 'node:zlib';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import jwt from 'jsonwebtoken';
import mongoose, { Schema } from 'mongoose';
import multer from 'multer';
import Stripe from 'stripe';

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


export function getAllowedCorsOrigins() {
  const raw = [
    process.env.FRONTEND_URL,
    process.env.APP_URL,
    process.env.CORS_ORIGINS,
    toHttpsOrigin(process.env.VERCEL_URL),
    toHttpsOrigin(process.env.VERCEL_PROJECT_PRODUCTION_URL),
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5000',
  ]
    .filter(Boolean)
    .join(',');

  return Array.from(
    new Set(
      raw
        .split(',')
        .map((item) => item.trim().replace(/\/$/, ''))
        .filter((item) => item && item !== 'MY_APP_URL')
    )
  );
}

export function isOriginAllowed(origin) {
  if (!origin) return true;
  const normalized = origin.replace(/\/$/, '');
  const allowList = getAllowedCorsOrigins();
  if (allowList.includes(normalized)) return true;

  try {
    const parsed = new URL(normalized);
    if (
      parsed.hostname === 'localhost' ||
      parsed.hostname === '127.0.0.1' ||
      parsed.hostname.endsWith('.vercel.app') ||
      parsed.hostname.endsWith('.onrender.com') ||
      parsed.hostname.endsWith('.run.app')
    ) {
      return true;
    }
  } catch {
    return false;
  }

  return false;
}

export function getFrontendBaseUrl(reqOrigin) {
  const envUrl = process.env.FRONTEND_URL?.trim() || process.env.APP_URL?.trim();
  const normalizedEnv = envUrl && envUrl !== 'MY_APP_URL' ? envUrl.replace(/\/$/, '') : '';
  const normalizedOrigin = reqOrigin ? reqOrigin.replace(/\/$/, '') : '';

  const envIsLocal =
    !normalizedEnv ||
    normalizedEnv.includes('localhost') ||
    normalizedEnv.includes('127.0.0.1');
  const originIsLive =
    Boolean(normalizedOrigin) &&
    !normalizedOrigin.includes('localhost') &&
    !normalizedOrigin.includes('127.0.0.1');

  if (originIsLive && envIsLocal) {
    return normalizedOrigin;
  }
  if (normalizedEnv) {
    return normalizedEnv;
  }
  if (normalizedOrigin) {
    return normalizedOrigin;
  }
  return 'http://localhost:3000';
}

export function resolveRequestOrigin(req) {
  const headerOrigin = typeof req?.headers?.origin === 'string' ? req.headers.origin.trim() : '';
  if (headerOrigin && isOriginAllowed(headerOrigin)) {
    return headerOrigin.replace(/\/$/, '');
  }
  const forwardedHost = String(req?.headers?.['x-forwarded-host'] || req?.headers?.host || '')
    .split(',')[0]
    .trim();
  const forwardedProto = String(req?.headers?.['x-forwarded-proto'] || (req?.secure ? 'https' : 'http'))
    .split(',')[0]
    .trim();
  if (
    forwardedHost &&
    !forwardedHost.startsWith('127.0.0.1:5000') &&
    !forwardedHost.startsWith('localhost:5000')
  ) {
    const computed = `${forwardedProto}://${forwardedHost}`.replace(/\/$/, '');
    if (isOriginAllowed(computed)) {
      return computed;
    }
  }
  return getFrontendBaseUrl(headerOrigin);
}

export function getBackendPublicBaseUrl() {
  const configured = process.env.BACKEND_PUBLIC_URL?.trim();
  return configured ? configured.replace(/\/$/, '') : '';
}

export function isHttpsRuntime() {
  return (
    getFrontendBaseUrl().startsWith('https://') ||
    process.env.NODE_ENV === 'production'
  );
}

export function isRequestHttps(req) {
  if (!req) return isHttpsRuntime();
  const forwardedProto = String(req.headers?.['x-forwarded-proto'] || '')
    .split(',')[0]
    .trim()
    .toLowerCase();
  if (forwardedProto === 'https') return true;
  if (forwardedProto === 'http') return false;

  const origin = String(req.headers?.origin || req.headers?.referer || '').trim().toLowerCase();
  if (origin.startsWith('https://')) return true;
  if (origin.startsWith('http://')) return false;

  if (req.secure) return true;
  const host = String(req.headers?.['x-forwarded-host'] || req.headers?.host || '').toLowerCase();
  if (host.startsWith('localhost') || host.startsWith('127.0.0.1')) return false;
  return isHttpsRuntime();
}

export function shouldSeedDemoData() {
  if (process.env.SEED_DEMO_DATA === 'true') return true;
  if (process.env.SEED_DEMO_DATA === 'false') return false;
  return process.env.NODE_ENV !== 'production';
}


export const SALON_CATEGORIES = [
  'Haircut & Styling',
  'Hair Coloring',
  'Hair Treatment',
  'Facial & Skincare',
  'Makeup',
  'Manicure & Pedicure',
  'Spa & Massage',
];

export const PREDEFINED_TIME_SLOTS = [
  '09:00 AM',
  '10:30 AM',
  '12:00 PM',
  '01:30 PM',
  '03:00 PM',
  '04:30 PM',
  '06:00 PM',
];

export function sanitizeUser(user) {
  if (!user) return null;
  const { passwordHash: _ignored, ...rest } = user;
  return rest;
}


export function isSafeImageUrl(url) {
  if (typeof url !== 'string') return false;
  const trimmed = url.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith('/') && !trimmed.startsWith('//')) return true;
  if (/^data:image\/(jpeg|jpg|png|webp|gif);base64,/i.test(trimmed)) return true;
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

export function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 6) {
    return { valid: false, message: 'Password must be at least 6 characters long.' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter.' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter.' };
  }
  return { valid: true };
}

export function validateServiceInput(input) {
  if (!input || typeof input.serviceName !== 'string' || !input.serviceName.trim()) {
    return { valid: false, message: 'Service name is required.' };
  }
  if (typeof input.category !== 'string' || !SALON_CATEGORIES.includes(input.category)) {
    return { valid: false, message: 'Please select a valid service category.' };
  }
  const priceNum = Number(input.price);
  if (!Number.isFinite(priceNum) || priceNum <= 0) {
    return { valid: false, message: 'Price must be a positive number.' };
  }
  const durationNum = Number(input.duration);
  if (!Number.isFinite(durationNum) || durationNum <= 0) {
    return { valid: false, message: 'Estimated duration must be a positive number.' };
  }
  if (typeof input.image !== 'string' || !input.image.trim()) {
    return { valid: false, message: 'Service image upload is required.' };
  }
  if (!isSafeImageUrl(input.image)) {
    return { valid: false, message: 'Please provide a valid image URL or uploaded image.' };
  }
  return { valid: true };
}

export function filterAndSortServices(services, options = {}) {
  const { search = '', category = 'All', sort = 'newest', includeInactive = false } = options;
  const normalizedSearch = typeof search === 'string' ? search.trim().toLowerCase() : '';

  const filtered = services.filter((svc) => {
    if (!includeInactive && svc.status !== 'active') return false;
    if (category && category !== 'All' && svc.category !== category) return false;
    if (normalizedSearch) {
      const haystack = `${svc.serviceName || ''} ${svc.category || ''} ${svc.description || ''}`.toLowerCase();
      if (!haystack.includes(normalizedSearch)) {
        return false;
      }
    }
    return true;
  });

  return [...filtered].sort((a, b) => {
    if (sort === 'price_asc') return a.price - b.price;
    if (sort === 'price_desc') return b.price - a.price;
    return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
  });
}


export function hasBookingConflict(appointments, params) {
  const activeOnDateSlot = appointments.filter(
    (apt) =>
      apt.status !== 'cancelled' &&
      apt.appointmentDate === params.appointmentDate &&
      apt.timeSlot === params.timeSlot
  );

  const sameServiceConflict = activeOnDateSlot.some((apt) => apt.serviceId === params.serviceId);
  if (sameServiceConflict) {
    return {
      conflict: true,
      reason: 'This time slot is already booked for this service. Please choose another slot.',
    };
  }

  const sameCustomerConflict = activeOnDateSlot.some((apt) => apt.customerId === params.customerId);
  if (sameCustomerConflict) {
    return {
      conflict: true,
      reason: 'You already have an active appointment request for this date and time slot.',
    };
  }

  return { conflict: false };
}


export function canCustomerCancelAppointment(appointment, customerId) {
  return appointment.customerId === customerId && appointment.status === 'pending';
}

export function canCustomerPayAppointment(appointment, customerId) {
  return (
    appointment.customerId === customerId &&
    appointment.status === 'confirmed' &&
    appointment.paymentStatus === 'unpaid'
  );
}

export function canAdminConfirmAppointment(appointment) {
  return appointment.status === 'pending';
}

export function canAdminCancelAppointment(appointment) {
  return appointment.status === 'pending' || appointment.status === 'confirmed';
}

export function validateAppointmentDate(appointmentDate, referenceDateStr) {
  if (
    !appointmentDate ||
    typeof appointmentDate !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}$/.test(appointmentDate)
  ) {
    return { valid: false, message: 'Please provide a valid date in YYYY-MM-DD format.' };
  }
  const [y, m, d] = appointmentDate.split('-').map(Number);
  const parsed = new Date(Date.UTC(y, m - 1, d));
  if (
    Number.isNaN(parsed.getTime()) ||
    parsed.getUTCFullYear() !== y ||
    parsed.getUTCMonth() !== m - 1 ||
    parsed.getUTCDate() !== d
  ) {
    return { valid: false, message: 'Please provide a valid calendar date.' };
  }
  const todayStr = referenceDateStr || new Date().toISOString().slice(0, 10);
  if (appointmentDate < todayStr) {
    return {
      valid: false,
      message: 'Past dates cannot be booked. Please choose today or a future date.',
    };
  }
  return { valid: true };
}

function buildServiceFallback(apt, serviceMap) {
  const live = serviceMap.get(apt.serviceId);
  if (live) return live;
  if (!apt.serviceName) return null;
  return {
    id: apt.serviceId,
    serviceName: apt.serviceName,
    image: apt.serviceImage || '',
    price: apt.servicePrice,
    duration: 60,
    category: 'Haircut & Styling',
    description: '',
    status: 'inactive',
    createdAt: apt.createdAt,
  };
}


const UserSchema = new Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
    passwordHash: { type: String, required: true },
    image: { type: String, default: '/images/service_facial_skincare_1795006415243.jpg' },
    phone: { type: String, default: '' },
    role: { type: String, enum: ['customer', 'admin'], default: 'customer', index: true },
    isBlocked: { type: Boolean, default: false },
    authProvider: {
      type: String,
      enum: ['credentials', 'google'],
      default: 'credentials',
    },
    createdAt: { type: String, default: () => new Date().toISOString() },
  },
  { versionKey: false }
);

const ServiceSchema = new Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    serviceName: { type: String, required: true, trim: true },
    category: { type: String, enum: [...SALON_CATEGORIES], required: true, index: true },
    description: { type: String, default: '', trim: true },
    price: { type: Number, required: true, min: 1 },
    duration: { type: Number, required: true, min: 5 },
    image: { type: String, required: true },
    status: { type: String, enum: ['active', 'inactive'], default: 'active', index: true },
    createdAt: { type: String, default: () => new Date().toISOString() },
  },
  { versionKey: false }
);
ServiceSchema.index({ status: 1, createdAt: -1 });

const AppointmentSchema = new Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    serviceId: { type: String, required: true, index: true },
    serviceName: { type: String, default: '' },
    serviceImage: { type: String, default: '' },
    customerId: { type: String, required: true, index: true },
    appointmentDate: { type: String, required: true, index: true },
    timeSlot: { type: String, required: true },
    message: { type: String, default: '' },
    servicePrice: { type: Number, required: true },
    paymentStatus: { type: String, enum: ['unpaid', 'paid'], default: 'unpaid' },
    status: {
      type: String,
      enum: ['pending', 'confirmed', 'cancelled'],
      default: 'pending',
      index: true,
    },
    stripeSessionId: { type: String },
    createdAt: { type: String, default: () => new Date().toISOString() },
  },
  { versionKey: false }
);
AppointmentSchema.index({ appointmentDate: 1, status: 1 });
AppointmentSchema.index({ customerId: 1, createdAt: -1 });

const TransactionSchema = new Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    appointmentId: { type: String, required: true, index: true },
    customerId: { type: String, required: true, index: true },
    amount: { type: Number, required: true },
    currency: { type: String, default: 'usd' },
    stripeSessionId: { type: String, required: true, index: true },
    status: { type: String, enum: ['paid', 'failed'], required: true },
    createdAt: { type: String, default: () => new Date().toISOString() },
  },
  { versionKey: false }
);
TransactionSchema.index({ status: 1, createdAt: -1 });

const CheckoutSessionSchema = new Schema(
  {
    sessionId: { type: String, required: true, unique: true, index: true },
    appointmentId: { type: String, required: true, index: true },
    customerId: { type: String, required: true, index: true },
    serviceName: { type: String, required: true },
    amount: { type: Number, required: true },
    currency: { type: String, default: 'usd' },
    mode: { type: String, enum: ['stripe', 'test_simulator'], default: 'test_simulator' },
    status: {
      type: String,
      enum: ['pending', 'completed', 'failed', 'expired'],
      default: 'pending',
    },
    expiresAt: { type: String, required: true },
    createdAt: { type: String, default: () => new Date().toISOString() },
  },
  { versionKey: false }
);

const UserModel = mongoose.models.User || mongoose.model('User', UserSchema);
const ServiceModel = mongoose.models.Service || mongoose.model('Service', ServiceSchema);
const AppointmentModel =
  mongoose.models.Appointment || mongoose.model('Appointment', AppointmentSchema);
const TransactionModel =
  mongoose.models.Transaction || mongoose.model('Transaction', TransactionSchema);
const CheckoutSessionModel =
  mongoose.models.CheckoutSession || mongoose.model('CheckoutSession', CheckoutSessionSchema);


export function createSeedData(options = {}) {
  const demoAllowed =
    typeof options.includeDemo === 'boolean' ? options.includeDemo : shouldSeedDemoData();
  const envAdminEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase() || '';
  const envAdminPassword = process.env.ADMIN_PASSWORD?.trim() || '';

  const users = [];
  if (envAdminEmail && envAdminPassword) {
    users.push({
      id: 'usr-admin-1',
      name: process.env.ADMIN_NAME?.trim() || 'Camille Laurent',
      email: envAdminEmail,
      passwordHash: bcrypt.hashSync(envAdminPassword, 10),
      image: '/images/stylist_camille_director_1795011102351.jpg',
      phone: '+1 (415) 890-2410',
      role: 'admin',
      isBlocked: false,
      authProvider: 'credentials',
      createdAt: '2026-09-01T09:00:00.000Z',
    });
  } else if (demoAllowed) {
    users.push({
      id: 'usr-admin-1',
      name: 'Camille Laurent',
      email: 'admin@salonbook.com',
      passwordHash: bcrypt.hashSync('Admin123', 10),
      image: '/images/stylist_camille_director_1795011102351.jpg',
      phone: '+1 (415) 890-2410',
      role: 'admin',
      isBlocked: false,
      authProvider: 'credentials',
      createdAt: '2026-09-01T09:00:00.000Z',
    });
  }

  const envCustomerEmail = (
    process.env.CUSTOMER_EMAIL ||
    process.env.CUSTOME_EMAIL ||
    (demoAllowed ? 'customer@salonbook.com' : '')
  ).trim().toLowerCase();
  const envCustomerPassword = (
    process.env.CUSTOMER_PASSWORD ||
    process.env.CUSTOME_PASSWORD ||
    (demoAllowed ? 'Customer123' : '')
  ).trim();

  if (envCustomerEmail && envCustomerPassword) {
    users.push({
      id: 'usr-cust-1',
      name: 'Maya Lin',
      email: envCustomerEmail,
      passwordHash: bcrypt.hashSync(envCustomerPassword, 10),
      image: '/images/service_hair_coloring_1795006415664.jpg',
      phone: '+1 (415) 555-0199',
      role: 'customer',
      isBlocked: false,
      authProvider: 'credentials',
      createdAt: '2026-09-02T10:00:00.000Z',
    });
  }

  if (!demoAllowed) {
    return { users, services: [], appointments: [], transactions: [], checkoutSessions: [] };
  }

  const services = [
    {
      id: 'svc-1',
      serviceName: 'Architectural Precision Haircut & Blowout',
      category: 'Haircut & Styling',
      description:
        'A bespoke consultation followed by a tailored wet-and-dry precision cut, botanical scalp cleanse, and signature luminous round-brush blowout.',
      price: 110,
      duration: 60,
      image: '/images/service_haircut_styling_1795006414399.jpg',
      status: 'active',
      createdAt: '2026-10-01T09:00:00.000Z',
    },
    {
      id: 'svc-2',
      serviceName: 'Lived-In Dimensional Balayage',
      category: 'Hair Coloring',
      description:
        'Hand-painted sunlit highlights customized to your skin tone, paired with a bond-building gloss toner for seamless grow-out and radiant shine.',
      price: 240,
      duration: 150,
      image: '/images/service_hair_coloring_1795006415664.jpg',
      status: 'active',
      createdAt: '2026-10-02T09:00:00.000Z',
    },
    {
      id: 'svc-3',
      serviceName: 'Botanical Keratin Renewal Ritual',
      category: 'Hair Treatment',
      description:
        'Deep restorative amino-acid and plant-protein infusion sealed with gentle thermal mist to smooth frizz and restore elasticity for up to 12 weeks.',
      price: 175,
      duration: 90,
      image: '/images/service_hair_treatment_ritual_1795011102653.jpg',
      status: 'active',
      createdAt: '2026-10-03T09:00:00.000Z',
    },
    {
      id: 'svc-4',
      serviceName: 'Hydra-Botanical Cellular Facial',
      category: 'Facial & Skincare',
      description:
        'Multi-step enzymatic exfoliation, ultrasonic pore purification, lymphatic facial sculpting massage, and cold-pressed botanical serum infusion.',
      price: 155,
      duration: 75,
      image: '/images/service_facial_skincare_1795006415243.jpg',
      status: 'active',
      createdAt: '2026-10-04T09:00:00.000Z',
    },
    {
      id: 'svc-5',
      serviceName: 'Editorial Soft-Glam Makeup Session',
      category: 'Makeup',
      description:
        'Skin-first radiant complexion prep and tailored editorial eye and lip artistry designed for weddings, galas, and studio photography.',
      price: 135,
      duration: 60,
      image: '/images/service_makeup_artistry_1795006416654.jpg',
      status: 'active',
      createdAt: '2026-10-05T09:00:00.000Z',
    },
    {
      id: 'svc-6',
      serviceName: 'Japanese Gel Manicure & Nail Care',
      category: 'Manicure & Pedicure',
      description:
        'Detailed e-file cuticle refinement, strengthening builder base overlay, warm rosemary oil soak, and sheer neutral or custom lacquer finish.',
      price: 85,
      duration: 60,
      image: '/images/service_manicure_pedicure_1795006418859.jpg',
      status: 'active',
      createdAt: '2026-10-06T09:00:00.000Z',
    },
    {
      id: 'svc-7',
      serviceName: 'Warm Basalt Stone Restorative Massage',
      category: 'Spa & Massage',
      description:
        'Slow-paced full-body therapeutic massage blending heated volcanic basalt stones with aromatic eucalyptus and sweet almond oil.',
      price: 165,
      duration: 90,
      image: '/images/service_spa_massage_1795006417265.jpg',
      status: 'active',
      createdAt: '2026-10-07T09:00:00.000Z',
    },
    {
      id: 'svc-8',
      serviceName: 'Restorative Spa Pedicure & Mineral Soak',
      category: 'Manicure & Pedicure',
      description:
        'Warm sea-salt and chamomile foot bath, gentle pumice resurfacing, reflexology calf massage, and long-wear mineral polish.',
      price: 95,
      duration: 60,
      image: '/images/service_manicure_pedicure_1795006418859.jpg',
      status: 'active',
      createdAt: '2026-10-08T09:00:00.000Z',
    },
    {
      id: 'svc-9',
      serviceName: 'Winter Solstice Aromatherapy Wrap',
      category: 'Spa & Massage',
      description:
        'Seasonal full-body mineral clay and warm cedarwood aromatherapy wrap designed for deep hydration and calm muscle relief.',
      price: 190,
      duration: 90,
      image: '/images/service_spa_massage_1795006417265.jpg',
      status: 'inactive',
      createdAt: '2026-10-09T09:00:00.000Z',
    },
  ];

  return { users, services, appointments: [], transactions: [], checkoutSessions: [] };
}