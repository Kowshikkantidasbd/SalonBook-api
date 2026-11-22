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
import { betterAuth } from 'better-auth';
import { toNodeHandler } from 'better-auth/node';
import { mongodbAdapter } from 'better-auth/adapters/mongodb';




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
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET environment variable is required in production.');
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

  return dbPath;
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

// ============================================================================
// 3. Mongoose Schemas & Models
// ============================================================================

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
  const envAdminEmail = (process.env.ADMIN_EMAIL).trim().toLowerCase();
  const envAdminPassword = (process.env.ADMIN_PASSWORD).trim();

  const users = [
    {
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
    },
  ];

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

// ============================================================================
// 5. MongoDB (Mongoose) & In-Memory Fallback Repository
// ============================================================================

class SalonRepository {
  constructor() {
    this.useMongo = false;
    this.initialized = false;
    this.initPromise = null;
    this.lastMongoAttemptAt = 0;
    this.lastMongoError = null;
    this.mongoListenersAttached = false;
    this.pendingSessions = new Map();
    this.localData = null;
    this._cache = new Map();
  }

  attachMongoLifecycleListeners() {
    if (this.mongoListenersAttached) return;
    this.mongoListenersAttached = true;

    mongoose.connection.on('connected', () => {
      this.useMongo = true;
      this.lastMongoError = null;
      this.invalidateCache();
    });

    mongoose.connection.on('disconnected', () => {
      this.useMongo = false;
      this.invalidateCache();
    });

    mongoose.connection.on('error', (err) => {
      this.lastMongoError = sanitizeMongoError(err);
    });
  }

  getCached(key) {
    const entry = this._cache.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this._cache.delete(key);
      return undefined;
    }
    return entry.value;
  }

  setCached(key, value, ttlMs = 20000) {
    this._cache.set(key, { value, expiresAt: Date.now() + ttlMs });
    return value;
  }

  invalidateCache(...prefixes) {
    if (prefixes.length === 0) {
      this._cache.clear();
      return;
    }
    for (const key of this._cache.keys()) {
      if (prefixes.some((p) => key.startsWith(p))) {
        this._cache.delete(key);
      }
    }
  }

  getMemoryStore() {
    if (!this.localData) {
      this.localData = createSeedData();
    }
    return this.localData;
  }

  async init() {
    if (this.useMongo && mongoose.connection.readyState === 1) {
      return { mode: 'mongodb' };
    }

    const mongoUri = getMongoUri();
    const retryCooldownMs = 15000;
    const canRetryMongo =
      Boolean(mongoUri) &&
      (!this.lastMongoAttemptAt || Date.now() - this.lastMongoAttemptAt >= retryCooldownMs);

    if (this.initialized && !canRetryMongo) {
      return { mode: this.useMongo ? 'mongodb' : 'memory_fallback' };
    }
    if (this.initPromise) {
      return this.initPromise;
    }

    this.initPromise = (async () => {
      if (mongoUri) {
        this.attachMongoLifecycleListeners();
        this.lastMongoAttemptAt = Date.now();
        try {
          if (mongoose.connection.readyState !== 1) {
            const dbName = resolveMongoDbName(mongoUri);
            await mongoose.connect(mongoUri, {
              ...(dbName ? { dbName } : {}),
              serverSelectionTimeoutMS: isServerless ? 8000 : 12000,
              connectTimeoutMS: isServerless ? 8000 : 12000,
              maxPoolSize: isServerless ? 5 : 20,
              minPoolSize: isServerless ? 0 : 2,
              maxIdleTimeMS: isServerless ? 30000 : 60000,
            });
          }
          this.useMongo = true;
          this.lastMongoError = null;
          await this.ensureMongoSeeded();
          this.initialized = true;
          this.invalidateCache();
          console.log(
            `SalonBook database connected: MongoDB (Mongoose, db="${mongoose.connection.name}")`
          );
          return { mode: 'mongodb' };
        } catch (err) {
          this.lastMongoError = sanitizeMongoError(err);
          this.useMongo = false;
          if (process.env.NODE_ENV === 'production') {
            throw new Error(`MongoDB connection failed in production: ${this.lastMongoError}`);
          }
          console.warn(
            'MongoDB connection failed, using in-memory seeded fallback repository (will retry automatically):',
            this.lastMongoError
          );
        }
      } else {
        if (process.env.NODE_ENV === 'production') {
          throw new Error('MONGODB_URI environment variable is required in production.');
        }
      }

      this.getMemoryStore();
      this.initialized = true;
      console.log('SalonBook database initialized: in-memory seeded fallback store');
      return { mode: 'memory_fallback' };
    })();

    try {
      return await this.initPromise;
    } finally {
      this.initPromise = null;
    }
  }

  getStorageMode() {
    return this.useMongo && mongoose.connection.readyState === 1 ? 'mongodb' : 'memory_fallback';
  }

  async getHealthDetails() {
    const mongoConfigured = Boolean(getMongoUri());
    const mongoConnected = Boolean(this.useMongo && mongoose.connection?.readyState === 1);

    if (!mongoConnected) {
      return {
        database: 'memory_fallback',
        mongoConfigured,
        mongoConnected: false,
        databaseName: null,
        collections: null,
        ...(this.lastMongoError ? { lastMongoError: this.lastMongoError } : {}),
      };
    }

    try {
      const [users, services, appointments, transactions, checkoutSessions] = await Promise.all([
        UserModel.countDocuments(),
        ServiceModel.countDocuments(),
        AppointmentModel.countDocuments(),
        TransactionModel.countDocuments(),
        CheckoutSessionModel.countDocuments(),
      ]);

      return {
        database: 'mongodb',
        mongoConfigured,
        mongoConnected: true,
        databaseName: mongoose.connection.name || null,
        collections: {
          users,
          services,
          appointments,
          transactions,
          checkoutSessions,
        },
      };
    } catch (err) {
      return {
        database: 'mongodb',
        mongoConfigured,
        mongoConnected: true,
        databaseName: mongoose.connection.name || null,
        collections: null,
        lastMongoError: sanitizeMongoError(err),
      };
    }
  }

  async ensureMongoSeeded() {
    const legacyDemoCustomerEmails = ['customer@salonbook.com', 'maya@salonbook.com'];
    const legacyDemoUsers = await UserModel.find(
      {
        role: 'customer',
        $or: [
          { id: { $in: ['usr-cust-1', 'usr-cust-2'] } },
          { email: { $in: legacyDemoCustomerEmails } },
        ],
      },
      { id: 1 }
    ).lean();
    const legacyDemoCustomerIds = Array.from(
      new Set(['usr-cust-1', 'usr-cust-2', ...legacyDemoUsers.map((u) => u.id).filter(Boolean)])
    );
    const legacyDemoAppointmentIds = ['apt-1001', 'apt-1002', 'apt-1003', 'apt-1004'];
    const legacyDemoTransactionIds = ['txn-5001'];
    const legacyDemoSessionIds = ['cs_test_a1b2c3d4e5f6'];

    await Promise.all([
      AppointmentModel.deleteMany({
        $or: [
          { id: { $in: legacyDemoAppointmentIds } },
          { customerId: { $in: legacyDemoCustomerIds } },
          { stripeSessionId: { $in: legacyDemoSessionIds } },
        ],
      }),
      TransactionModel.deleteMany({
        $or: [
          { id: { $in: legacyDemoTransactionIds } },
          { customerId: { $in: legacyDemoCustomerIds } },
          { appointmentId: { $in: legacyDemoAppointmentIds } },
          { stripeSessionId: { $in: legacyDemoSessionIds } },
        ],
      }),
      CheckoutSessionModel.deleteMany({
        $or: [
          { customerId: { $in: legacyDemoCustomerIds } },
          { appointmentId: { $in: legacyDemoAppointmentIds } },
          { sessionId: { $in: legacyDemoSessionIds } },
        ],
      }),
      UserModel.deleteMany({
        role: 'customer',
        email: /^diag_(test|debug)_\d+@example\.com$/i,
      }),
    ]);

    const [userCount, serviceCount] = await Promise.all([
      UserModel.countDocuments(),
      ServiceModel.countDocuments(),
    ]);

    if (userCount === 0 || serviceCount === 0) {
      const seed = createSeedData();
      const safeInsertMany = async (model, docs) => {
        if (!docs || docs.length === 0) return;
        try {
          await model.insertMany(docs, { ordered: false });
        } catch (err) {
          if (err?.code !== 11000 && !String(err?.message || '').includes('E11000')) {
            throw err;
          }
        }
      };

      if (userCount === 0 && seed.users.length > 0) {
        await safeInsertMany(UserModel, seed.users);
      }
      if (serviceCount === 0 && seed.services.length > 0) {
        await safeInsertMany(ServiceModel, seed.services);
      }
    }

    const envAdminEmail = (process.env.ADMIN_EMAIL ).trim().toLowerCase();
    const envAdminPassword = (process.env.ADMIN_PASSWORD).trim();
    const envCustomerEmail = (
      process.env.CUSTOMER_EMAIL ||
      process.env.CUSTOME_EMAIL ||
      'customer@salonbook.com'
    ).trim().toLowerCase();
    const envCustomerPassword = (
      process.env.CUSTOMER_PASSWORD ||
      process.env.CUSTOME_PASSWORD ||
      'Customer123'
    ).trim();

    if (envAdminEmail && envAdminPassword) {
      const existingAdmin = await UserModel.findOne({ email: envAdminEmail });
      if (!existingAdmin) {
        await UserModel.create({
          id: 'usr-admin-1',
          name: process.env.ADMIN_NAME?.trim() || 'Camille Laurent',
          email: envAdminEmail,
          passwordHash: bcrypt.hashSync(envAdminPassword, 10),
          image: '/images/stylist_camille_director_1795011102351.jpg',
          phone: '+1 (415) 890-2410',
          role: 'admin',
          isBlocked: false,
          authProvider: 'credentials',
          createdAt: new Date().toISOString(),
        });
      }
    }

    if (envCustomerEmail && envCustomerPassword) {
      const existingCustomer = await UserModel.findOne({ email: envCustomerEmail });
      if (!existingCustomer) {
        await UserModel.create({
          id: 'usr-cust-1',
          name: 'Maya Lin',
          email: envCustomerEmail,
          passwordHash: bcrypt.hashSync(envCustomerPassword, 10),
          image: '/images/service_hair_coloring_1795006415664.jpg',
          phone: '+1 (415) 555-0199',
          role: 'customer',
          isBlocked: false,
          authProvider: 'credentials',
          createdAt: new Date().toISOString(),
        });
      }
    }
  }

  stripMongoId(doc) {
    if (!doc) return null;
    const { _id: _removed, ...rest } = doc;
    return rest;
  }

  // --- USERS ---
  async findUserByEmail(email) {
    if (typeof email !== 'string') return null;
    const normalized = email.trim().toLowerCase();
    if (!normalized) return null;
    if (this.useMongo) {
      const doc = await UserModel.findOne({ email: normalized }).lean();
      return this.stripMongoId(doc);
    }
    const mem = this.getMemoryStore();
    return mem.users.find((u) => u.email.toLowerCase() === normalized) || null;
  }

  async findUserById(id) {
    if (typeof id !== 'string' || !id) return null;
    const cacheKey = `user:${id}`;
    const cached = this.getCached(cacheKey);
    if (cached !== undefined) return cached;

    let result;
    if (this.useMongo) {
      const doc = await UserModel.findOne({ id }).lean();
      result = this.stripMongoId(doc);
    } else {
      result = this.getMemoryStore().users.find((u) => u.id === id) || null;
    }
    if (result) {
      this.setCached(cacheKey, result, 15000);
    }
    return result;
  }

  async createUser(user) {
    if (this.useMongo) {
      await UserModel.create(user);
    } else {
      this.getMemoryStore().users.push(user);
    }
    this.invalidateCache(`user:${user.id}`, 'stats:');
    return user;
  }

  async updateUserProfile(id, updates) {
    if (typeof id !== 'string' || !id) return null;
    let result;
    if (this.useMongo) {
      const setObj = {};
      if (typeof updates.name === 'string' && updates.name.trim()) {
        setObj.name = updates.name.trim();
      }
      if (typeof updates.phone === 'string') setObj.phone = updates.phone;
      if (typeof updates.image === 'string' && updates.image.trim()) {
        setObj.image = updates.image.trim();
      }
      const updated = await UserModel.findOneAndUpdate({ id }, { $set: setObj }, { new: true }).lean();
      result = this.stripMongoId(updated);
    } else {
      const existing = this.getMemoryStore().users.find((u) => u.id === id);
      if (!existing) return null;
      if (typeof updates.name === 'string' && updates.name.trim()) {
        existing.name = updates.name.trim();
      }
      if (typeof updates.phone === 'string') existing.phone = updates.phone;
      if (typeof updates.image === 'string' && updates.image.trim()) {
        existing.image = updates.image.trim();
      }
      result = existing;
    }
    this.invalidateCache(`user:${id}`);
    return result;
  }

  async setUserBlocked(id, isBlocked) {
    if (typeof id !== 'string' || !id) return null;
    let result;
    if (this.useMongo) {
      const updated = await UserModel.findOneAndUpdate(
        { id },
        { $set: { isBlocked: Boolean(isBlocked) } },
        { new: true }
      ).lean();
      result = this.stripMongoId(updated);
    } else {
      const existing = this.getMemoryStore().users.find((u) => u.id === id);
      if (!existing) return null;
      existing.isBlocked = Boolean(isBlocked);
      result = existing;
    }
    this.invalidateCache(`user:${id}`);
    return result;
  }

  async listUsers() {
    if (this.useMongo) {
      const docs = await UserModel.find().lean();
      return docs.map((d) => this.stripMongoId(d));
    }
    return this.getMemoryStore().users;
  }

  // --- SERVICES ---
  async _getRawServices(includeInactive = false) {
    const cacheKey = includeInactive ? 'services:all' : 'services:active';
    const cached = this.getCached(cacheKey);
    if (cached !== undefined) return cached;

    let list;
    if (this.useMongo) {
      const query = includeInactive ? {} : { status: 'active' };
      const docs = await ServiceModel.find(query).lean();
      list = docs.map((d) => this.stripMongoId(d));
    } else {
      const raw = this.getMemoryStore().services;
      list = includeInactive ? [...raw] : raw.filter((s) => s.status === 'active');
    }
    return this.setCached(cacheKey, list, 30000);
  }

  async listServices(options = {}) {
    const base = await this._getRawServices(Boolean(options.includeInactive));
    return filterAndSortServices(base, options);
  }

  async findServiceById(id) {
    if (typeof id !== 'string' || !id) return null;
    const allCached = this.getCached('services:all') || this.getCached('services:active');
    if (allCached) {
      const found = allCached.find((s) => s.id === id);
      if (found) return found;
    }
    const cacheKey = `service:${id}`;
    const cached = this.getCached(cacheKey);
    if (cached !== undefined) return cached;

    let result;
    if (this.useMongo) {
      const doc = await ServiceModel.findOne({ id }).lean();
      result = this.stripMongoId(doc);
    } else {
      result = this.getMemoryStore().services.find((s) => s.id === id) || null;
    }
    if (result) {
      this.setCached(cacheKey, result, 30000);
    }
    return result;
  }

  async createService(service) {
    if (this.useMongo) {
      await ServiceModel.create(service);
    } else {
      this.getMemoryStore().services.unshift(service);
    }
    this.invalidateCache('services:', 'service:', 'stats:');
    return service;
  }

  async updateService(id, updates) {
    if (typeof id !== 'string' || !id) return null;
    let result;
    if (this.useMongo) {
      const updated = await ServiceModel.findOneAndUpdate({ id }, { $set: updates }, { new: true }).lean();
      result = this.stripMongoId(updated);
    } else {
      const existing = this.getMemoryStore().services.find((s) => s.id === id);
      if (!existing) return null;
      Object.assign(existing, updates);
      result = existing;
    }
    this.invalidateCache('services:', 'service:', 'stats:');
    return result;
  }

  async deleteService(id) {
    if (typeof id !== 'string' || !id) return false;
    let deleted;
    if (this.useMongo) {
      const res = await ServiceModel.deleteOne({ id });
      deleted = res.deletedCount > 0;
    } else {
      const mem = this.getMemoryStore();
      const idx = mem.services.findIndex((s) => s.id === id);
      if (idx === -1) return false;
      mem.services.splice(idx, 1);
      deleted = true;
    }
    this.invalidateCache('services:', 'service:', 'stats:');
    return deleted;
  }

  // --- APPOINTMENTS ---
  async listAppointments() {
    if (this.useMongo) {
      const docs = await AppointmentModel.find().sort({ createdAt: -1 }).lean();
      return docs.map((d) => this.stripMongoId(d));
    }
    return [...this.getMemoryStore().appointments].sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  async listAppointmentsByCustomer(customerId) {
    if (typeof customerId !== 'string' || !customerId) return [];
    if (this.useMongo) {
      const docs = await AppointmentModel.find({ customerId }).sort({ createdAt: -1 }).lean();
      return docs.map((d) => this.stripMongoId(d));
    }
    return this.getMemoryStore()
      .appointments.filter((a) => a.customerId === customerId)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  async findAppointmentById(id) {
    if (typeof id !== 'string' || !id) return null;
    if (this.useMongo) {
      const doc = await AppointmentModel.findOne({ id }).lean();
      return this.stripMongoId(doc);
    }
    return this.getMemoryStore().appointments.find((a) => a.id === id) || null;
  }

  async findAppointmentBySessionId(sessionId) {
    if (typeof sessionId !== 'string' || !sessionId) return null;
    if (this.useMongo) {
      const doc = await AppointmentModel.findOne({ stripeSessionId: sessionId }).lean();
      return this.stripMongoId(doc);
    }
    return this.getMemoryStore().appointments.find((a) => a.stripeSessionId === sessionId) || null;
  }

  async listBookedSlots(serviceId, customerId, date) {
    const safeServiceId = typeof serviceId === 'string' ? serviceId : '';
    const safeCustomerId = typeof customerId === 'string' ? customerId : '';
    const safeDate = typeof date === 'string' ? date : '';
    if (this.useMongo) {
      const docs = await AppointmentModel.find({
        appointmentDate: safeDate,
        status: { $ne: 'cancelled' },
        $or: [{ serviceId: safeServiceId }, { customerId: safeCustomerId }],
      })
        .select('timeSlot -_id')
        .lean();
      return docs.map((d) => d.timeSlot);
    }
    return this.getMemoryStore()
      .appointments.filter(
        (apt) =>
          apt.status !== 'cancelled' &&
          apt.appointmentDate === safeDate &&
          (apt.serviceId === safeServiceId || apt.customerId === safeCustomerId)
      )
      .map((apt) => apt.timeSlot);
  }

  async listActiveAppointmentsForSlot(appointmentDate, timeSlot) {
    const safeDate = typeof appointmentDate === 'string' ? appointmentDate : '';
    const safeSlot = typeof timeSlot === 'string' ? timeSlot : '';
    if (this.useMongo) {
      const docs = await AppointmentModel.find({
        appointmentDate: safeDate,
        timeSlot: safeSlot,
        status: { $ne: 'cancelled' },
      })
        .select('id serviceId customerId appointmentDate timeSlot status -_id')
        .lean();
      return docs;
    }
    return this.getMemoryStore().appointments.filter(
      (apt) =>
        apt.status !== 'cancelled' &&
        apt.appointmentDate === safeDate &&
        apt.timeSlot === safeSlot
    );
  }

  async countAppointmentsByCustomerMap() {
    if (this.useMongo) {
      const rows = await AppointmentModel.aggregate([
        { $group: { _id: '$customerId', count: { $sum: 1 } } },
      ]);
      const map = new Map();
      for (const row of rows) {
        map.set(row._id, row.count);
      }
      return map;
    }
    const map = new Map();
    for (const apt of this.getMemoryStore().appointments) {
      map.set(apt.customerId, (map.get(apt.customerId) || 0) + 1);
    }
    return map;
  }

  async getAdminStats() {
    const cached = this.getCached('stats:admin');
    if (cached !== undefined) return cached;

    if (this.useMongo) {
      const [
        totalCustomers,
        totalActiveServices,
        totalAppointments,
        pendingAppointments,
        confirmedAppointments,
        paidAgg,
      ] = await Promise.all([
        UserModel.countDocuments({ role: 'customer' }),
        ServiceModel.countDocuments({ status: 'active' }),
        AppointmentModel.countDocuments(),
        AppointmentModel.countDocuments({ status: 'pending' }),
        AppointmentModel.countDocuments({ status: 'confirmed' }),
        TransactionModel.aggregate([
          { $match: { status: 'paid' } },
          {
            $group: {
              _id: null,
              count: { $sum: 1 },
              totalRevenue: { $sum: '$amount' },
            },
          },
        ]),
      ]);
      const paidSummary = paidAgg[0] || { count: 0, totalRevenue: 0 };
      return this.setCached(
        'stats:admin',
        {
          totalCustomers,
          totalActiveServices,
          totalAppointments,
          pendingAppointments,
          confirmedAppointments,
          totalSuccessfulPayments: paidSummary.count,
          totalRevenue: paidSummary.totalRevenue,
        },
        20000
      );
    }

    const mem = this.getMemoryStore();
    const paidTxns = mem.transactions.filter((t) => t.status === 'paid');
    return this.setCached(
      'stats:admin',
      {
        totalCustomers: mem.users.filter((u) => u.role === 'customer').length,
        totalActiveServices: mem.services.filter((s) => s.status === 'active').length,
        totalAppointments: mem.appointments.length,
        pendingAppointments: mem.appointments.filter((a) => a.status === 'pending').length,
        confirmedAppointments: mem.appointments.filter((a) => a.status === 'confirmed').length,
        totalSuccessfulPayments: paidTxns.length,
        totalRevenue: paidTxns.reduce((sum, t) => sum + t.amount, 0),
      },
      20000
    );
  }

  async countAppointmentsByService(serviceId) {
    if (typeof serviceId !== 'string' || !serviceId) return 0;
    if (this.useMongo) {
      return AppointmentModel.countDocuments({ serviceId });
    }
    return this.getMemoryStore().appointments.filter((a) => a.serviceId === serviceId).length;
  }

  async createAppointment(appointment) {
    if (this.useMongo) {
      await AppointmentModel.create(appointment);
    } else {
      this.getMemoryStore().appointments.unshift(appointment);
    }
    this.invalidateCache('stats:');
    return appointment;
  }

  async updateAppointment(id, updates) {
    if (typeof id !== 'string' || !id) return null;
    let result;
    if (this.useMongo) {
      const updated = await AppointmentModel.findOneAndUpdate(
        { id },
        { $set: updates },
        { new: true }
      ).lean();
      result = this.stripMongoId(updated);
    } else {
      const existing = this.getMemoryStore().appointments.find((a) => a.id === id);
      if (!existing) return null;
      Object.assign(existing, updates);
      result = existing;
    }
    this.invalidateCache('stats:');
    return result;
  }

  // --- TRANSACTIONS ---
  async listTransactions() {
    if (this.useMongo) {
      const docs = await TransactionModel.find().sort({ createdAt: -1 }).lean();
      return docs.map((d) => this.stripMongoId(d));
    }
    return [...this.getMemoryStore().transactions].sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  async listTransactionsByCustomer(customerId) {
    if (typeof customerId !== 'string' || !customerId) return [];
    if (this.useMongo) {
      const docs = await TransactionModel.find({ customerId }).sort({ createdAt: -1 }).lean();
      return docs.map((d) => this.stripMongoId(d));
    }
    return this.getMemoryStore()
      .transactions.filter((t) => t.customerId === customerId)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  async findTransactionBySessionId(sessionId) {
    if (typeof sessionId !== 'string' || !sessionId) return null;
    if (this.useMongo) {
      const doc = await TransactionModel.findOne({ stripeSessionId: sessionId }).lean();
      return this.stripMongoId(doc);
    }
    return this.getMemoryStore().transactions.find((t) => t.stripeSessionId === sessionId) || null;
  }

  async applyVerifiedPayment(params) {
    const appointment = await this.findAppointmentById(params.appointmentId);
    if (!appointment) return;

    const mem = this.useMongo ? null : this.getMemoryStore();
    const existingPaid = this.useMongo
      ? await TransactionModel.findOne({
          stripeSessionId: params.stripeSessionId,
          status: 'paid',
        }).lean()
      : mem.transactions.find(
          (t) => t.stripeSessionId === params.stripeSessionId && t.status === 'paid'
        );

    if (existingPaid) {
      if (params.status === 'paid' && appointment.paymentStatus !== 'paid') {
        await this.updateAppointment(params.appointmentId, {
          paymentStatus: 'paid',
          stripeSessionId: params.stripeSessionId,
        });
        this.invalidateCache('stats:');
      }
      return;
    }

    if (params.status === 'paid') {
      await this.updateAppointment(params.appointmentId, {
        paymentStatus: 'paid',
        stripeSessionId: params.stripeSessionId,
      });
    }

    const transaction = {
      id: `txn-${crypto.randomUUID().slice(0, 8)}`,
      appointmentId: params.appointmentId,
      customerId: params.customerId || appointment.customerId,
      amount: params.amount,
      currency: params.currency,
      stripeSessionId: params.stripeSessionId,
      status: params.status,
      createdAt: new Date().toISOString(),
    };

    if (this.useMongo) {
      await TransactionModel.create(transaction);
    } else {
      mem.transactions.unshift(transaction);
    }

    this.pendingSessions.delete(params.stripeSessionId);
    await this.markCheckoutSessionStatus(
      params.stripeSessionId,
      params.status === 'paid' ? 'completed' : 'failed'
    );
    this.invalidateCache('stats:');
  }

  // --- PERSISTENT CHECKOUT SESSIONS ---
  async createCheckoutSession(session) {
    this.pendingSessions.set(session.sessionId, session);
    if (this.useMongo) {
      await CheckoutSessionModel.findOneAndUpdate(
        { sessionId: session.sessionId },
        { $set: session },
        { upsert: true, new: true }
      );
      return session;
    }
    const store = this.getMemoryStore();
    if (!store.checkoutSessions) store.checkoutSessions = [];
    store.checkoutSessions.unshift(session);
    return session;
  }

  async findCheckoutSession(sessionId) {
    if (typeof sessionId !== 'string' || !sessionId) return null;
    if (this.useMongo) {
      const doc = await CheckoutSessionModel.findOne({ sessionId }).lean();
      return this.stripMongoId(doc);
    }
    const mem = this.getMemoryStore();
    const fromStore = (mem.checkoutSessions || []).find((s) => s.sessionId === sessionId);
    return fromStore || this.pendingSessions.get(sessionId) || null;
  }

  async markCheckoutSessionStatus(sessionId, status) {
    if (typeof sessionId !== 'string' || !sessionId) return;
    if (status !== 'pending') {
      this.pendingSessions.delete(sessionId);
    }
    if (this.useMongo) {
      await CheckoutSessionModel.updateOne({ sessionId }, { $set: { status } });
      return;
    }
    const mem = this.getMemoryStore();
    const existing = (mem.checkoutSessions || []).find((s) => s.sessionId === sessionId);
    if (existing) existing.status = status;
  }
}

export const db = new SalonRepository();

// ============================================================================
// 6. JWT Authentication & Multer Upload Middleware
// ============================================================================

export function signAuthToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
    },
    getJwtSecret(),
    { expiresIn: '7d' }
  );
}

export function verifyAuthToken(token) {
  return jwt.verify(token, getJwtSecret());
}

export function extractTokenFromRequest(req) {
  const authHeader = req.headers?.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    if (token) return { token, source: 'bearer' };
  }

  const cookieHeader = req.headers?.cookie;
  if (cookieHeader) {
    const cookies = cookieHeader.split(';');
    for (const part of cookies) {
      const idx = part.indexOf('=');
      if (idx === -1) continue;
      const key = part.slice(0, idx).trim();
      const value = part.slice(idx + 1).trim();
      if (key === 'salonbook_token' && value) {
        try {
          return { token: decodeURIComponent(value), source: 'cookie' };
        } catch {
          return { token: value, source: 'cookie' };
        }
      }
    }
  }

  return { token: null, source: null };
}

function setAuthCookie(res, token, req) {
  const useCrossSiteCookies = isRequestHttps(req);
  const maxAgeSeconds = 7 * 24 * 60 * 60;
  const parts = [
    `salonbook_token=${encodeURIComponent(token)}`,
    'Path=/',
    `Max-Age=${maxAgeSeconds}`,
    'HttpOnly',
    useCrossSiteCookies ? 'SameSite=None' : 'SameSite=Lax',
  ];
  if (useCrossSiteCookies) {
    parts.push('Secure', 'Partitioned');
  }
  res.append('Set-Cookie', parts.join('; '));
}

function clearAuthCookie(res, req) {
  const useCrossSiteCookies = isRequestHttps(req);
  const parts = [
    'salonbook_token=',
    'Path=/',
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    'HttpOnly',
    useCrossSiteCookies ? 'SameSite=None' : 'SameSite=Lax',
  ];
  if (useCrossSiteCookies) {
    parts.push('Secure', 'Partitioned');
  }
  res.append('Set-Cookie', parts.join('; '));
}

function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

export async function requireAuth(req, res, next) {
  const { token, source } = extractTokenFromRequest(req);
  if (!token) {
    try {
      const session = await auth.api.getSession({ headers: req.headers }).catch(() => null);
      if (session?.user) {
        const liveUser =
          (await db.findUserByEmail(session.user.email)) ||
          (await db.findUserById(session.user.id));
        if (liveUser) {
          if (liveUser.isBlocked) {
            res.status(403).json({
              error: 'Your account has been blocked by an administrator.',
              code: 'ACCOUNT_BLOCKED',
            });
            return;
          }
          req.user = sanitizeUser(liveUser);
          next();
          return;
        }
      }
    } catch {
      // Fall through to 401
    }
    res.status(401).json({ error: 'Authentication required. Please sign in.' });
    return;
  }

  // Protect cookie-authenticated state-changing requests by verifying Origin when present
  const method = String(req.method || 'GET').toUpperCase();
  if (source === 'cookie' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const reqOrigin = req.headers?.origin;
    if (reqOrigin && !isOriginAllowed(reqOrigin)) {
      res.status(403).json({ error: 'Request origin is not permitted.' });
      return;
    }
  }

  try {
    const decoded = verifyAuthToken(token);
    if (!decoded || typeof decoded.sub !== 'string') {
      res.status(401).json({ error: 'Invalid authentication token. Please sign in again.' });
      return;
    }

    const liveUser = await db.findUserById(decoded.sub);
    if (!liveUser) {
      res.status(401).json({ error: 'Session expired. Please sign in again.' });
      return;
    }

    if (liveUser.isBlocked) {
      res.status(403).json({
        error: 'Your account has been blocked by an administrator.',
        code: 'ACCOUNT_BLOCKED',
      });
      return;
    }

    req.user = sanitizeUser(liveUser);
    next();
  } catch {
    res.status(401).json({ error: 'Authentication required. Please sign in.' });
  }
}

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    if (!roles.includes(req.user.role)) {
      const error =
        roles.includes('customer') && req.user.role === 'admin'
          ? 'Administrator accounts cannot submit customer bookings or payments. Please sign in with a customer account.'
          : 'Administrator permission is required to access this resource.';
      res.status(403).json({
        error,
        code: 'FORBIDDEN_ROLE',
      });
      return;
    }
    next();
  };
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (!allowed.includes(file.mimetype)) {
      cb(new Error('Only JPEG, PNG, WEBP, or GIF images are allowed.'));
      return;
    }
    cb(null, true);
  },
});

const uploadRateWindowMs = 10 * 60 * 1000;
const uploadRateLimitMax = 20;
const uploadRateBuckets = new Map();

function uploadRateLimit(req, res, next) {
  const key = req.user?.id || req.ip || 'anonymous';
  const now = Date.now();
  const entry = uploadRateBuckets.get(key);
  if (!entry || now > entry.resetAt) {
    uploadRateBuckets.set(key, { count: 1, resetAt: now + uploadRateWindowMs });
    next();
    return;
  }
  if (entry.count >= uploadRateLimitMax) {
    res.status(429).json({
      error: 'Too many image uploads. Please wait a few minutes before uploading again.',
    });
    return;
  }
  entry.count += 1;
  next();
}

// ============================================================================
// 7. ImgBB Image Hosting & Stripe Payment Services
// ============================================================================

const IMAGE_EXT_MAP = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
  'image/gif': '.gif',
};

async function uploadImageToImgbbOrLocal(file) {
  const imgbbKey = getImgbbApiKey();

  if (imgbbKey) {
    const form = new URLSearchParams();
    form.append('key', imgbbKey);
    form.append('image', file.buffer.toString('base64'));

    let imgbbRes;
    try {
      imgbbRes = await fetch('https://api.imgbb.com/1/upload', {
        method: 'POST',
        body: form,
      });
    } catch {
      const err = new Error('Failed to connect to ImgBB image service.');
      err.statusCode = 502;
      throw err;
    }

    const imgbbJson = await imgbbRes.json().catch(() => ({}));
    if (!imgbbRes.ok || !imgbbJson.success || !imgbbJson.data?.url) {
      const err = new Error(imgbbJson.error?.message || 'ImgBB image hosting failed.');
      err.statusCode = 502;
      throw err;
    }

    return { url: imgbbJson.data.url, provider: 'imgbb' };
  }

  if (process.env.NODE_ENV === 'production' || isServerless) {
    const err = new Error('IMGBB_API_KEY environment variable is required for image hosting in production.');
    err.statusCode = 503;
    throw err;
  }

  const ext = IMAGE_EXT_MAP[file.mimetype] || '.jpg';
  const filename = `salon_${Date.now()}_${crypto.randomBytes(4).toString('hex')}${ext}`;
  const resolvedBase = path.resolve(UPLOADS_DIR);
  const targetPath = path.resolve(resolvedBase, filename);

  if (!targetPath.startsWith(resolvedBase + path.sep)) {
    const err = new Error('Invalid upload destination path.');
    err.statusCode = 400;
    throw err;
  }

  if (!fs.existsSync(resolvedBase)) {
    fs.mkdirSync(resolvedBase, { recursive: true });
  }
  fs.writeFileSync(targetPath, file.buffer);

  const baseUrl = getBackendPublicBaseUrl();
  return {
    url: baseUrl ? `${baseUrl}/uploads/${filename}` : `/uploads/${filename}`,
    provider: 'local',
  };
}

function getStripeClient() {
  const key = getStripeSecretKey();
  return key ? new Stripe(key) : null;
}

export async function processStripeWebhookEvent(rawBody, sig) {
  if (!sig || typeof sig !== 'string' || !Buffer.isBuffer(rawBody)) {
    const err = new Error('Missing Stripe webhook signature or raw payload.');
    err.statusCode = 400;
    throw err;
  }

  const stripe = getStripeClient();
  const webhookSecret = getStripeWebhookSecret();

  let eventType = '';
  let sessionData = null;

  if (
    stripe &&
    process.env.STRIPE_WEBHOOK_SECRET &&
    process.env.STRIPE_WEBHOOK_SECRET !== 'MY_STRIPE_WEBHOOK_SECRET'
  ) {
    const event = stripe.webhooks.constructEvent(rawBody, sig, webhookSecret);
    eventType = event.type;
    if (
      event.type === 'checkout.session.completed' ||
      event.type === 'checkout.session.async_payment_failed'
    ) {
      sessionData = event.data.object;
    }
  } else {
    const parts = Object.fromEntries(sig.split(',').map((p) => p.split('=')));
    const timestamp = parts['t'];
    const v1 = parts['v1'];
    if (!timestamp || !v1) {
      const err = new Error('Invalid webhook signature header format.');
      err.statusCode = 400;
      throw err;
    }
    const expected = crypto
      .createHmac('sha256', webhookSecret)
      .update(`${timestamp}.${rawBody.toString('utf-8')}`)
      .digest('hex');

    const valid =
      expected.length === v1.length &&
      crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(v1));
    if (!valid) {
      const err = new Error('Webhook signature verification failed.');
      err.statusCode = 400;
      throw err;
    }

    const parsed = JSON.parse(rawBody.toString('utf-8'));
    eventType = parsed.type;
    sessionData = parsed.data?.object ?? null;
  }

  if (eventType === 'checkout.session.completed' && sessionData?.metadata?.appointmentId) {
    await db.applyVerifiedPayment({
      appointmentId: sessionData.metadata.appointmentId,
      customerId: sessionData.metadata.customerId || '',
      amount: Number(
        sessionData.amount_total
          ? sessionData.amount_total / 100
          : sessionData.metadata.amount || 0
      ),
      currency: sessionData.currency || 'usd',
      stripeSessionId: sessionData.id,
      status: 'paid',
    });
  } else if (
    eventType === 'checkout.session.async_payment_failed' &&
    sessionData?.metadata?.appointmentId
  ) {
    await db.applyVerifiedPayment({
      appointmentId: sessionData.metadata.appointmentId,
      customerId: sessionData.metadata.customerId || '',
      amount: Number(
        sessionData.amount_total
          ? sessionData.amount_total / 100
          : sessionData.metadata.amount || 0
      ),
      currency: sessionData.currency || 'usd',
      stripeSessionId: sessionData.id,
      status: 'failed',
    });
  }

  return { received: true };
}

export function createStripeWebhookHandler() {
  return async (req, res) => {
    try {
      const result = await processStripeWebhookEvent(req.body, req.headers['stripe-signature']);
      res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Webhook error';
      const status = err?.statusCode || 400;
      res.status(status).json({ error: `Webhook verification error: ${msg}` });
    }
  };
}

export async function syncStripeCheckoutSession({
  sessionId,
  stripe = getStripeClient(),
  repository = db,
  expectedCustomerId = null,
  allowAdmin = false,
}) {
  if (!sessionId) {
    return { completed: false, session: null };
  }

  const existingTxn = await repository.findTransactionBySessionId(sessionId);
  if (existingTxn && existingTxn.status === 'paid') {
    if (expectedCustomerId && !allowAdmin && existingTxn.customerId !== expectedCustomerId) {
      const err = new Error('Forbidden.');
      err.statusCode = 403;
      throw err;
    }
    let apt = await repository.findAppointmentById(existingTxn.appointmentId);
    if (apt && apt.paymentStatus !== 'paid') {
      apt =
        (await repository.updateAppointment(apt.id, {
          paymentStatus: 'paid',
          stripeSessionId: sessionId,
        })) || apt;
    }
    return { completed: true, transaction: existingTxn, appointment: apt };
  }

  const storedSession = await repository.findCheckoutSession(sessionId);
  if (
    storedSession &&
    expectedCustomerId &&
    !allowAdmin &&
    storedSession.customerId !== expectedCustomerId
  ) {
    const err = new Error('Forbidden.');
    err.statusCode = 403;
    throw err;
  }

  if (stripe && storedSession?.mode !== 'test_simulator') {
    try {
      const stripeSession = await stripe.checkout.sessions.retrieve(sessionId);
      const fallbackApt =
        !stripeSession?.metadata?.appointmentId && !storedSession?.appointmentId
          ? await repository.findAppointmentBySessionId(sessionId)
          : null;
      const appointmentId =
        stripeSession?.metadata?.appointmentId ||
        storedSession?.appointmentId ||
        fallbackApt?.id ||
        '';
      const linkedApt = appointmentId
        ? await repository.findAppointmentById(appointmentId)
        : fallbackApt;
      const resolvedCustomerId =
        stripeSession?.metadata?.customerId ||
        storedSession?.customerId ||
        linkedApt?.customerId ||
        '';

      if (
        expectedCustomerId &&
        !allowAdmin &&
        resolvedCustomerId &&
        resolvedCustomerId !== expectedCustomerId
      ) {
        const err = new Error('Forbidden.');
        err.statusCode = 403;
        throw err;
      }

      const isStripePaid =
        stripeSession?.payment_status === 'paid' ||
        stripeSession?.payment_status === 'no_payment_required' ||
        (stripeSession?.status === 'complete' && stripeSession?.payment_status !== 'unpaid');

      if (isStripePaid && appointmentId) {
        // Payment status in database is ONLY updated by the verified Stripe webhook.
        const [existingTxnAfterWebhook, updatedApt] = await Promise.all([
          repository.findTransactionBySessionId(sessionId),
          repository.findAppointmentById(appointmentId),
        ]);
        if (existingTxnAfterWebhook && existingTxnAfterWebhook.status === 'paid') {
          return { completed: true, transaction: existingTxnAfterWebhook, appointment: updatedApt };
        }
        return {
          completed: false,
          session: storedSession || null,
          status: 'processing',
          message: 'Payment received by Stripe. Awaiting verified webhook processing.',
        };
      }

      if (stripeSession?.status === 'expired') {
        await repository.markCheckoutSessionStatus(sessionId, 'expired');
        return { completed: false, expired: true, session: storedSession || null };
      }
    } catch (err) {
      if (err?.statusCode === 403) {
        throw err;
      }
    }
  }

  return { completed: false, session: storedSession || null };
}

export async function reconcilePendingStripeAppointments(
  appointments,
  { stripe = getStripeClient(), repository = db, expectedCustomerId = null, allowAdmin = false } = {}
) {
  if (!stripe || !Array.isArray(appointments) || appointments.length === 0) {
    return { appointments, updatedCount: 0 };
  }

  const candidates = appointments
    .filter((apt) => apt && apt.paymentStatus !== 'paid' && apt.stripeSessionId)
    .slice(0, 5);

  if (candidates.length === 0) {
    return { appointments, updatedCount: 0 };
  }

  const syncedMap = new Map();
  await Promise.allSettled(
    candidates.map(async (apt) => {
      const result = await syncStripeCheckoutSession({
        sessionId: apt.stripeSessionId,
        stripe,
        repository,
        expectedCustomerId: allowAdmin ? null : expectedCustomerId || apt.customerId,
        allowAdmin,
      });
      if (result?.completed && result.appointment) {
        syncedMap.set(apt.id, result.appointment);
      }
    })
  );

  if (syncedMap.size === 0) {
    return { appointments, updatedCount: 0 };
  }

  return {
    appointments: appointments.map((apt) => syncedMap.get(apt.id) || apt),
    updatedCount: syncedMap.size,
  };
}

// ============================================================================
// 8. REST API Routes (/api/*)
// ============================================================================

const OAUTH_HANDOFF_TTL_MS = 90 * 1000;
const oauthPopupHandoffs = new Map();

function sanitizeSafeNextPath(raw) {
  if (typeof raw !== 'string') return '/dashboard';
  const trimmed = raw.trim();
  if (!trimmed.startsWith('/') || trimmed.startsWith('//')) return '/dashboard';
  return trimmed;
}

function createSignedOAuthState(payload) {
  return jwt.sign(
    {
      purpose: 'salonbook_google_oauth_state',
      nonce: crypto.randomBytes(12).toString('hex'),
      ...payload,
    },
    getJwtSecret(),
    { expiresIn: '10m' }
  );
}

function verifySignedOAuthState(stateToken) {
  if (!stateToken || typeof stateToken !== 'string') return null;
  try {
    const decoded = jwt.verify(stateToken, getJwtSecret());
    if (
      !decoded ||
      typeof decoded !== 'object' ||
      decoded.purpose !== 'salonbook_google_oauth_state'
    ) {
      return null;
    }
    return {
      handoffId: typeof decoded.handoffId === 'string' ? decoded.handoffId : '',
      next: sanitizeSafeNextPath(decoded.next),
      redirectUri: typeof decoded.redirectUri === 'string' ? decoded.redirectUri : '',
      origin: typeof decoded.origin === 'string' ? decoded.origin : '',
    };
  } catch {
    return null;
  }
}

function pruneExpiringMap(map) {
  const now = Date.now();
  for (const [key, entry] of map.entries()) {
    if (!entry || entry.expiresAt <= now) {
      map.delete(key);
    }
  }
}

function storeOAuthPopupHandoff(handoffId, payload) {
  if (!handoffId || typeof handoffId !== 'string' || handoffId.length < 12 || handoffId.length > 128) {
    return;
  }
  pruneExpiringMap(oauthPopupHandoffs);
  oauthPopupHandoffs.set(handoffId, {
    ...payload,
    expiresAt: Date.now() + OAUTH_HANDOFF_TTL_MS,
  });
}

function consumeOAuthPopupHandoff(handoffId) {
  if (!handoffId || typeof handoffId !== 'string') return null;
  pruneExpiringMap(oauthPopupHandoffs);
  const entry = oauthPopupHandoffs.get(handoffId);
  if (!entry) return null;
  oauthPopupHandoffs.delete(handoffId);
  return entry;
}

function renderOAuthPopupHtml(messagePayload, fallbackRedirect, targetOrigin, heading, subtitle) {
  const safeJson = JSON.stringify(messagePayload).replace(/</g, '\\u003c');
  const safeRedirect = JSON.stringify(fallbackRedirect || '/dashboard').replace(/</g, '\\u003c');
  const safeOrigin = JSON.stringify(targetOrigin || '*').replace(/</g, '\\u003c');
  const esc = (str) =>
    String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>SalonBook Authentication</title>
  </head>
  <body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#FBF8F3;color:#231A16;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:24px;text-align:center;">
    <div style="max-width:360px;background:#FFFFFF;border:1px solid #E5DDD0;border-radius:16px;padding:28px 24px;box-shadow:0 16px 36px -20px rgba(35,26,22,0.22);">
      <p style="font-size:16px;font-weight:600;margin:0 0 8px;">${esc(heading)}</p>
      <p style="font-size:13px;color:#6E6259;line-height:1.5;margin:0;">${esc(subtitle)}</p>
    </div>
    <script>
      (function () {
        var payload = ${safeJson};
        var redirectPath = ${safeRedirect};
        var targetOrigin = ${safeOrigin};
        try {
          if (window.opener && !window.opener.closed) {
            window.opener.postMessage(payload, targetOrigin);
            setTimeout(function () {
              try { window.close(); } catch (e) {}
            }, 150);
            return;
          }
        } catch (e) {}
        if (payload.type === 'SALONBOOK_OAUTH_SUCCESS') {
          window.location.replace(redirectPath);
        } else {
          setTimeout(function () {
            try { window.close(); } catch (e) {}
          }, 1200);
        }
      })();
    </script>
  </body>
</html>`;
}


const dynamicMongoDb = new Proxy({}, {
  get(_target, prop) {
    if (mongoose.connection && mongoose.connection.db) {
      const val = mongoose.connection.db[prop];
      if (typeof val === 'function') {
        return val.bind(mongoose.connection.db);
      }
      return val;
    }
    if (prop === 'collection') {
      return (name) => {
        if (mongoose.connection && mongoose.connection.db) {
          return mongoose.connection.db.collection(name);
        }
        return {
          createIndex: async () => {},
          findOne: async () => null,
          find: () => ({ toArray: async () => [] }),
          insertOne: async () => ({ insertedId: '1' }),
          updateOne: async () => ({ modifiedCount: 1 }),
          deleteOne: async () => ({ deletedCount: 1 }),
        };
      };
    }
    return undefined;
  },
});

export const auth = betterAuth({
  database: mongodbAdapter(dynamicMongoDb),
  secret: getJwtSecret(),
  baseURL:
    process.env.BETTER_AUTH_URL ||
    process.env.BACKEND_PUBLIC_URL ||
    process.env.BACKEND_URL ||
    `http://127.0.0.1:${getPort()}`,
  user: {
    additionalFields: {
      role: {
        type: 'string',
        defaultValue: 'customer',
        required: false,
      },
      isBlocked: {
        type: 'boolean',
        defaultValue: false,
        required: false,
      },
      phone: {
        type: 'string',
        defaultValue: '',
        required: false,
      },
    },
  },
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false,
  },
  ...(isGoogleSocialAuthEnabled()
    ? {
        socialProviders: {
          google: {
            clientId: getGoogleClientId(),
            clientSecret: getGoogleClientSecret(),
          },
        },
      }
    : {}),
});

// --- 8A. Auth & Profile Routes ---
function registerAuthRoutes(router) {
  router.post(
    '/auth/register',
    asyncHandler(async (req, res) => {
      const { name, email, password, image } = req.body || {};

      if (typeof name !== 'string' || !name.trim()) {
        res.status(400).json({ error: 'Full name is required.' });
        return;
      }
      if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
        res.status(400).json({ error: 'Please provide a valid email address.' });
        return;
      }

      const passCheck = validatePassword(password);
      if (!passCheck.valid) {
        res.status(400).json({ error: passCheck.message });
        return;
      }

      const safeImage =
        typeof image === 'string' && image.trim() && isSafeImageUrl(image)
          ? image.trim()
          : '/images/service_facial_skincare_1795006415243.jpg';

      const normalizedEmail = email.trim().toLowerCase();
      const existing = await db.findUserByEmail(normalizedEmail);
      if (existing) {
        res.status(409).json({ error: 'An account with this email already exists.' });
        return;
      }

      const passwordHash = await bcrypt.hash(password, 10);
      const newUser = await db.createUser({
        id: `usr-${crypto.randomUUID().slice(0, 8)}`,
        name: name.trim(),
        email: normalizedEmail,
        passwordHash,
        image: safeImage,
        phone: '',
        role: 'customer',
        isBlocked: false,
        authProvider: 'credentials',
        createdAt: new Date().toISOString(),
      });

      const token = signAuthToken(newUser);
      setAuthCookie(res, token, req);
      res.status(201).json({ token, user: sanitizeUser(newUser) });
    })
  );

  router.post(
    '/auth/login',
    asyncHandler(async (req, res) => {
      const { email, password } = req.body || {};
      const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
      if (!normalizedEmail || typeof password !== 'string' || !password) {
        res.status(400).json({ error: 'Email and password are required.' });
        return;
      }

      const user = await db.findUserByEmail(normalizedEmail);
      const verified = Boolean(user && (await bcrypt.compare(password, user.passwordHash)));

      if (!user || !verified) {
        res.status(401).json({ error: 'Invalid email or password.' });
        return;
      }

      if (user.isBlocked) {
        res.status(403).json({
          error: 'Your account has been blocked by an administrator.',
          code: 'ACCOUNT_BLOCKED',
        });
        return;
      }

      const token = signAuthToken(user);
      setAuthCookie(res, token, req);
      res.json({ token, user: sanitizeUser(user) });
    })
  );

  router.get('/auth/providers', (_req, res) => {
    res.json({
      jwt: true,
      google: isGoogleSocialAuthEnabled(),
    });
  });

  router.post(
    '/auth/google',
    asyncHandler(async (req, res) => {
      const { credential, accessToken, email, name, image, handoffId, next } = req.body || {};
      const safeNext = sanitizeSafeNextPath(next);

      let resolvedEmail = '';
      let resolvedName = '';
      let resolvedImage = '';

      if (typeof credential === 'string' && credential.trim()) {
        try {
          const verifyRes = await fetch(
            `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential.trim())}`
          );
          const data = await verifyRes.json().catch(() => ({}));
          if (!verifyRes.ok || !data.email) {
            throw new Error(data.error_description || 'Invalid Google credential token.');
          }
          const configuredClientId = getGoogleClientId();
          if (configuredClientId && data.aud && data.aud !== configuredClientId) {
            throw new Error('Google credential audience mismatch.');
          }
          resolvedEmail = String(data.email).trim().toLowerCase();
          resolvedName =
            typeof data.name === 'string' && data.name.trim()
              ? data.name.trim()
              : resolvedEmail.split('@')[0];
          resolvedImage =
            typeof data.picture === 'string' && isSafeImageUrl(data.picture)
              ? data.picture.trim()
              : '';
        } catch (err) {
          res.status(401).json({ error: err.message || 'Could not verify Google ID token.' });
          return;
        }
      } else if (typeof accessToken === 'string' && accessToken.trim()) {
        try {
          const profileRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
            headers: { Authorization: `Bearer ${accessToken.trim()}` },
          });
          const profile = await profileRes.json().catch(() => ({}));
          if (!profileRes.ok || typeof profile.email !== 'string' || !profile.email.trim()) {
            throw new Error('Could not retrieve user info from Google.');
          }
          resolvedEmail = profile.email.trim().toLowerCase();
          resolvedName =
            typeof profile.name === 'string' && profile.name.trim()
              ? profile.name.trim()
              : resolvedEmail.split('@')[0];
          resolvedImage =
            typeof profile.picture === 'string' && isSafeImageUrl(profile.picture)
              ? profile.picture.trim()
              : '';
        } catch (err) {
          res.status(401).json({ error: err.message || 'Could not verify Google access token.' });
          return;
        }
      } else if (typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
        resolvedEmail = email.trim().toLowerCase();
        resolvedName =
          typeof name === 'string' && name.trim() ? name.trim() : resolvedEmail.split('@')[0];
        resolvedImage = typeof image === 'string' && isSafeImageUrl(image) ? image.trim() : '';
      } else {
        res
          .status(400)
          .json({ error: 'Valid Google credential, access token, or email is required.' });
        return;
      }

      let user = await db.findUserByEmail(resolvedEmail);
      if (!user) {
        const placeholderHash = await bcrypt.hash(crypto.randomUUID(), 10);
        user = await db.createUser({
          id: `usr-${crypto.randomUUID().slice(0, 8)}`,
          name: resolvedName,
          email: resolvedEmail,
          passwordHash: placeholderHash,
          image: resolvedImage || '/images/service_hair_coloring_1795006415664.jpg',
          phone: '',
          role:
            resolvedEmail === (process.env.ADMIN_EMAIL?.trim().toLowerCase())
              ? 'admin'
              : 'customer',
          isBlocked: false,
          authProvider: 'google',
          createdAt: new Date().toISOString(),
        });
      } else if (
        resolvedImage &&
        (!user.image || user.image === '/images/service_hair_coloring_1795006415664.jpg')
      ) {
        const updated = await db.updateUserProfile(user.id, { image: resolvedImage });
        if (updated) user = updated;
      }

      if (user.isBlocked) {
        if (handoffId) {
          storeOAuthPopupHandoff(handoffId, {
            status: 'error',
            error: 'Your account has been blocked by an administrator.',
          });
        }
        res.status(403).json({ error: 'Your account has been blocked by an administrator.' });
        return;
      }

      const token = signAuthToken(user);
      const publicUser = sanitizeUser(user);
      setAuthCookie(res, token, req);

      if (handoffId) {
        storeOAuthPopupHandoff(handoffId, {
          status: 'success',
          token,
          user: publicUser,
          next: safeNext,
        });
      }

      res.json({
        token,
        user: publicUser,
        next: safeNext,
      });
    })
  );

  router.post(
    '/auth/google/start',
    asyncHandler(async (req, res) => {
      if (!isGoogleSocialAuthEnabled()) {
        res.status(503).json({
          error:
            'Google Sign-In is not configured on this server yet. Set GOOGLE_CLIENT_ID.',
          code: 'GOOGLE_AUTH_UNCONFIGURED',
        });
        return;
      }

      const { handoffId, next } = req.body || {};
      const safeHandoffId =
        typeof handoffId === 'string' && handoffId.trim().length >= 12 && handoffId.trim().length <= 128
          ? handoffId.trim()
          : crypto.randomUUID();
      const safeNext = sanitizeSafeNextPath(next);
      const origin = resolveRequestOrigin(req);
      const redirectUri = `${origin}/api/auth/callback/google`;

      const clientId = getGoogleClientId();

      const state = createSignedOAuthState({
        handoffId: safeHandoffId,
        next: safeNext,
        redirectUri,
        origin,
      });

      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        prompt: 'select_account',
        state,
      });

      res.json({
        url: `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`,
        handoffId: safeHandoffId,
      });
    })
  );

  router.get(
    ['/auth/callback/google', '/auth/callback/google/'],
    asyncHandler(async (req, res) => {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');

      const stateKey = typeof req.query.state === 'string' ? req.query.state.trim() : '';
      const code = typeof req.query.code === 'string' ? req.query.code.trim() : '';
      const rawError = typeof req.query.error === 'string' ? req.query.error.trim() : '';

      const stateEntry = verifySignedOAuthState(stateKey);

      const handoffId = stateEntry?.handoffId || '';
      const nextPath = stateEntry?.next || '/dashboard';
      const targetOrigin = stateEntry?.origin || resolveRequestOrigin(req);

      if (!stateEntry) {
        const message = 'Google sign-in session expired. Please try again.';
        res.send(
          renderOAuthPopupHtml(
            { type: 'SALONBOOK_OAUTH_ERROR', error: message },
            '/sign-in',
            targetOrigin,
            'Session Expired',
            'Please close this window and click Sign in with Google again.'
          )
        );
        return;
      }

      if (rawError || !code) {
        const message =
          rawError === 'access_denied'
            ? 'Google sign-in was cancelled.'
            : `Google sign-in failed (${rawError || 'missing_code'}).`;
        storeOAuthPopupHandoff(handoffId, { status: 'error', error: message });
        res.send(
          renderOAuthPopupHtml(
            { type: 'SALONBOOK_OAUTH_ERROR', error: message, handoff: handoffId },
            '/sign-in',
            targetOrigin,
            'Sign-In Cancelled',
            'You can close this window and return to SalonBook.'
          )
        );
        return;
      }

      try {
        if (!getGoogleClientSecret()) {
          const message =
            'Google Client Secret is missing in backend/.env. Please add GOOGLE_CLIENT_SECRET in backend/.env to complete OAuth authorization code exchange.';
          storeOAuthPopupHandoff(handoffId, { status: 'error', error: message });
          res.send(
            renderOAuthPopupHtml(
              { type: 'SALONBOOK_OAUTH_ERROR', error: message, handoff: handoffId },
              '/sign-in',
              targetOrigin,
              'Configuration Required',
              message
            )
          );
          return;
        }

        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code,
            client_id: getGoogleClientId(),
            client_secret: getGoogleClientSecret(),
            redirect_uri: stateEntry.redirectUri,
            grant_type: 'authorization_code',
          }),
        });

        const tokenData = await tokenRes.json().catch(() => ({}));
        if (!tokenRes.ok || !tokenData.access_token) {
          throw new Error(tokenData.error_description || 'Could not verify Google authorization code.');
        }

        const profileRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
          headers: { Authorization: `Bearer ${tokenData.access_token}` },
        });
        const profile = await profileRes.json().catch(() => ({}));
        if (!profileRes.ok || typeof profile.email !== 'string' || !profile.email.trim()) {
          throw new Error('Could not retrieve verified email from Google.');
        }

        const normalizedEmail = profile.email.trim().toLowerCase();
        const resolvedName =
          typeof profile.name === 'string' && profile.name.trim()
            ? profile.name.trim()
            : normalizedEmail.split('@')[0];
        const resolvedImage =
          typeof profile.picture === 'string' && isSafeImageUrl(profile.picture)
            ? profile.picture.trim()
            : '';

        let user = await db.findUserByEmail(normalizedEmail);
        if (!user) {
          const placeholderHash = await bcrypt.hash(crypto.randomUUID(), 10);
          user = await db.createUser({
            id: `usr-${crypto.randomUUID().slice(0, 8)}`,
            name: resolvedName,
            email: normalizedEmail,
            passwordHash: placeholderHash,
            image: resolvedImage || '/images/service_hair_coloring_1795006415664.jpg',
            phone: '',
            role: 'customer',
            isBlocked: false,
            authProvider: 'google',
            createdAt: new Date().toISOString(),
          });
        } else if (
          resolvedImage &&
          (!user.image || user.image === '/images/service_hair_coloring_1795006415664.jpg')
        ) {
          const updated = await db.updateUserProfile(user.id, { image: resolvedImage });
          if (updated) user = updated;
        }

        if (user.isBlocked) {
          const message = 'Your account has been blocked by an administrator.';
          storeOAuthPopupHandoff(handoffId, { status: 'error', error: message });
          res.send(
            renderOAuthPopupHtml(
              { type: 'SALONBOOK_OAUTH_ERROR', error: message, handoff: handoffId },
              '/sign-in',
              targetOrigin,
              'Account Blocked',
              message
            )
          );
          return;
        }

        const token = signAuthToken(user);
        const publicUser = sanitizeUser(user);
        setAuthCookie(res, token, req);
        storeOAuthPopupHandoff(handoffId, {
          status: 'success',
          token,
          user: publicUser,
          next: nextPath,
        });

        res.send(
          renderOAuthPopupHtml(
            {
              type: 'SALONBOOK_OAUTH_SUCCESS',
              token,
              user: publicUser,
              next: nextPath,
              handoff: handoffId,
            },
            nextPath,
            targetOrigin,
            'Signed In with Google',
            'Returning to your SalonBook account now...'
          )
        );
      } catch (err) {
        const message =
          err instanceof Error && err.message
            ? err.message
            : 'Google sign-in failed. Please try again.';
        storeOAuthPopupHandoff(handoffId, { status: 'error', error: message });
        res.send(
          renderOAuthPopupHtml(
            { type: 'SALONBOOK_OAUTH_ERROR', error: message, handoff: handoffId },
            '/sign-in',
            targetOrigin,
            'Authentication Failed',
            'Returning to SalonBook so you can try again.'
          )
        );
      }
    })
  );

  router.get('/auth/popup-status', (req, res) => {
    const handoffId = typeof req.query.handoff === 'string' ? req.query.handoff.trim() : '';
    const entry = consumeOAuthPopupHandoff(handoffId);
    if (!entry) {
      res.json({ status: 'pending' });
      return;
    }
    if (entry.status === 'error') {
      res.json({ status: 'error', error: entry.error });
      return;
    }
    if (entry.token) {
      setAuthCookie(res, entry.token, req);
    }
    res.json({
      status: 'success',
      token: entry.token,
      user: entry.user,
      next: entry.next || '/dashboard',
    });
  });

  router.post('/auth/logout', (req, res) => {
    clearAuthCookie(res, req);
    res.json({ ok: true });
  });

  router.get('/auth/me', requireAuth, (req, res) => {
    res.json({ user: req.user });
  });

  router.get('/profile', requireAuth, (req, res) => {
    res.json({ user: req.user });
  });

  router.put(
    '/profile',
    requireAuth,
    asyncHandler(async (req, res) => {
      const { name, image, phone } = req.body || {};

      if (typeof name !== 'string' || !name.trim()) {
        res.status(400).json({ error: 'Full name cannot be empty.' });
        return;
      }

      if (typeof image === 'string' && image.trim() && !isSafeImageUrl(image)) {
        res.status(400).json({ error: 'Please provide a valid image URL.' });
        return;
      }

      const updated = await db.updateUserProfile(req.user.id, {
        name: name.trim(),
        phone: typeof phone === 'string' ? phone.trim() : undefined,
        image: typeof image === 'string' && image.trim() ? image.trim() : undefined,
      });

      if (!updated) {
        res.status(404).json({ error: 'User not found.' });
        return;
      }
      res.json({ user: sanitizeUser(updated) });
    })
  );
  // Mount Better Auth handler for /api/auth/* endpoints (sign-in, sign-up, session, ok, etc.)
  router.all('/auth/*', toNodeHandler(auth));
}

// --- 8B. Image Upload Route (ImgBB) ---
function registerUploadRoutes(router) {
  router.post('/upload', requireAuth, uploadRateLimit, (req, res) => {
    upload.single('image')(req, res, async (err) => {
      if (err) {
        res.status(400).json({ error: err.message || 'Image upload failed.' });
        return;
      }
      if (!req.file) {
        res.status(400).json({ error: 'No image file provided.' });
        return;
      }

      try {
        const result = await uploadImageToImgbbOrLocal(req.file);
        res.json({ url: result.url, provider: result.provider });
      } catch (uploadErr) {
        const status = uploadErr?.statusCode || 502;
        const message =
          uploadErr instanceof Error ? uploadErr.message : 'Image upload failed.';
        res.status(status).json({ error: message });
      }
    });
  });
}

// --- 8C. Salon Services Catalog & Admin CRUD Routes ---
function registerServiceRoutes(router) {
  router.get(
    '/services',
    asyncHandler(async (req, res) => {
      const search = typeof req.query.search === 'string' ? req.query.search : '';
      const category = typeof req.query.category === 'string' ? req.query.category : 'All';
      const sortParam = req.query.sort;
      const sort =
        sortParam === 'price_asc' || sortParam === 'price_desc' ? sortParam : 'newest';

      const activeServices = await db.listServices({
        search,
        category,
        sort,
        includeInactive: false,
      });
      res.setHeader('Cache-Control', 'public, max-age=30, stale-while-revalidate=120');
      res.json({ services: activeServices });
    })
  );

  router.get(
    '/services/:id',
    asyncHandler(async (req, res) => {
      const id = String(req.params.id);
      const service = await db.findServiceById(id);
      if (!service) {
        res.status(404).json({ error: 'Salon service not found. Please check the service link.' });
        return;
      }
      if (service.status !== 'active') {
        let isAdmin = false;
        const { token } = extractTokenFromRequest(req);
        if (token) {
          try {
            const decoded = verifyAuthToken(token);
            const liveUser = await db.findUserById(decoded.sub);
            isAdmin = Boolean(liveUser && !liveUser.isBlocked && liveUser.role === 'admin');
          } catch {
            isAdmin = false;
          }
        }
        if (!isAdmin) {
          res.status(404).json({
            error: 'This service is currently inactive and unavailable for booking.',
          });
          return;
        }
        res.setHeader('Cache-Control', 'private, no-store');
        res.json({ service });
        return;
      }
      res.setHeader('Cache-Control', 'public, max-age=30, stale-while-revalidate=120');
      res.json({ service });
    })
  );

  router.get(
    '/admin/services',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (_req, res) => {
      const all = await db.listServices({ includeInactive: true, sort: 'newest' });
      res.json({ services: all });
    })
  );

  router.post(
    '/admin/services',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (req, res) => {
      const body = req.body || {};
      const validation = validateServiceInput(body);
      if (!validation.valid) {
        res.status(400).json({ error: validation.message });
        return;
      }

      const newService = await db.createService({
        id: `svc-${crypto.randomUUID().slice(0, 8)}`,
        serviceName: body.serviceName.trim(),
        category: body.category,
        description: typeof body.description === 'string' ? body.description.trim() : '',
        price: Number(body.price),
        duration: Math.round(Number(body.duration)),
        image: body.image.trim(),
        status: body.status === 'inactive' ? 'inactive' : 'active',
        createdAt: new Date().toISOString(),
      });

      res.status(201).json({ service: newService });
    })
  );

  router.put(
    '/admin/services/:id',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (req, res) => {
      const id = String(req.params.id);
      const body = req.body || {};
      const validation = validateServiceInput(body);
      if (!validation.valid) {
        res.status(400).json({ error: validation.message });
        return;
      }

      const updated = await db.updateService(id, {
        serviceName: body.serviceName.trim(),
        category: body.category,
        description: typeof body.description === 'string' ? body.description.trim() : '',
        price: Number(body.price),
        duration: Math.round(Number(body.duration)),
        image: body.image.trim(),
        ...(body.status === 'active' || body.status === 'inactive' ? { status: body.status } : {}),
      });

      if (!updated) {
        res.status(404).json({ error: 'Service not found.' });
        return;
      }
      res.json({ service: updated });
    })
  );

  router.patch(
    '/admin/services/:id/status',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (req, res) => {
      const id = String(req.params.id);
      const { status } = req.body || {};
      if (status !== 'active' && status !== 'inactive') {
        res.status(400).json({ error: 'Status must be active or inactive.' });
        return;
      }
      const updated = await db.updateService(id, { status });
      if (!updated) {
        res.status(404).json({ error: 'Service not found.' });
        return;
      }
      res.json({ service: updated });
    })
  );

  router.delete(
    '/admin/services/:id',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (req, res) => {
      const id = String(req.params.id);
      const existingAppointments = await db.countAppointmentsByService(id);
      if (existingAppointments > 0) {
        res.status(409).json({
          error:
            'This service has existing appointment records and cannot be deleted. Set its status to "inactive" instead to hide it from new bookings.',
        });
        return;
      }
      const deleted = await db.deleteService(id);
      if (!deleted) {
        res.status(404).json({ error: 'Service not found.' });
        return;
      }
      res.json({ ok: true });
    })
  );
}

// --- 8D. Appointments Routes ---
function registerAppointmentRoutes(router) {
  router.get(
    '/appointments/slots',
    requireAuth,
    asyncHandler(async (req, res) => {
      const serviceId = typeof req.query.serviceId === 'string' ? req.query.serviceId : '';
      const date = typeof req.query.date === 'string' ? req.query.date : '';
      if (!serviceId || !date) {
        res.status(400).json({ error: 'serviceId and date are required.' });
        return;
      }

      const dateCheck = validateAppointmentDate(date);
      if (!dateCheck.valid) {
        res.status(400).json({ error: dateCheck.message });
        return;
      }

      const bookedSlots = await db.listBookedSlots(serviceId, req.user?.id || '', date);

      res.json({
        slots: PREDEFINED_TIME_SLOTS.map((slot) => ({
          timeSlot: slot,
          available: !bookedSlots.includes(slot),
        })),
      });
    })
  );

  router.post(
    '/appointments',
    requireAuth,
    requireRole('customer'),
    asyncHandler(async (req, res) => {
      const { serviceId, appointmentDate, timeSlot, message } = req.body || {};

      if (
        typeof serviceId !== 'string' ||
        typeof appointmentDate !== 'string' ||
        typeof timeSlot !== 'string' ||
        !serviceId ||
        !appointmentDate ||
        !timeSlot
      ) {
        res.status(400).json({ error: 'Service, date, and time slot are required.' });
        return;
      }

      const dateCheck = validateAppointmentDate(appointmentDate);
      if (!dateCheck.valid) {
        res.status(400).json({ error: dateCheck.message });
        return;
      }

      if (!PREDEFINED_TIME_SLOTS.includes(timeSlot)) {
        res.status(400).json({ error: 'Please select a valid predefined time slot.' });
        return;
      }

      const service = await db.findServiceById(serviceId);
      if (!service) {
        res.status(404).json({ error: 'Selected service was not found.' });
        return;
      }
      if (service.status !== 'active') {
        res.status(400).json({ error: 'Cannot book an inactive service.' });
        return;
      }

      const slotAppointments = await db.listActiveAppointmentsForSlot(appointmentDate, timeSlot);
      const conflict = hasBookingConflict(slotAppointments, {
        serviceId,
        customerId: req.user.id,
        appointmentDate,
        timeSlot,
      });

      if (conflict.conflict) {
        res.status(409).json({ error: conflict.reason });
        return;
      }

      const trimmedMessage = typeof message === 'string' ? message.trim() : '';
      if (trimmedMessage.length > 1000) {
        res.status(400).json({ error: 'Additional notes must be 1000 characters or fewer.' });
        return;
      }

      const appointment = {
        id: `apt-${crypto.randomUUID().slice(0, 8)}`,
        serviceId: service.id,
        serviceName: service.serviceName,
        serviceImage: service.image,
        customerId: req.user.id,
        appointmentDate,
        timeSlot,
        message: trimmedMessage,
        servicePrice: service.price,
        paymentStatus: 'unpaid',
        status: 'pending',
        createdAt: new Date().toISOString(),
      };

      await db.createAppointment(appointment);
      res.status(201).json({
        appointment: {
          ...appointment,
          service,
        },
      });
    })
  );

  router.get(
    '/appointments/my',
    requireAuth,
    requireRole('customer'),
    asyncHandler(async (req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      const [mine, allServices] = await Promise.all([
        db.listAppointmentsByCustomer(req.user.id),
        db.listServices({ includeInactive: true }),
      ]);
      const { appointments: reconciled } = await reconcilePendingStripeAppointments(mine, {
        expectedCustomerId: req.user.id,
      });
      const serviceMap = new Map(allServices.map((s) => [s.id, s]));
      res.json({
        appointments: reconciled.map((apt) => ({
          ...apt,
          service: buildServiceFallback(apt, serviceMap),
        })),
      });
    })
  );

  router.patch(
    '/appointments/:id/cancel',
    requireAuth,
    requireRole('customer'),
    asyncHandler(async (req, res) => {
      const id = String(req.params.id);
      const apt = await db.findAppointmentById(id);
      if (!apt) {
        res.status(404).json({ error: 'Appointment not found.' });
        return;
      }
      if (apt.customerId !== req.user.id) {
        res.status(403).json({ error: 'You can only manage your own appointments.' });
        return;
      }
      if (apt.status === 'cancelled') {
        res.json({ appointment: apt, alreadyUpdated: true });
        return;
      }
      if (!canCustomerCancelAppointment(apt, req.user.id)) {
        res.status(400).json({ error: 'Only pending appointment requests can be cancelled.' });
        return;
      }

      const updated = await db.updateAppointment(id, { status: 'cancelled' });
      res.json({ appointment: updated });
    })
  );

  router.get(
    '/customer/stats',
    requireAuth,
    requireRole('customer'),
    asyncHandler(async (req, res) => {
      const mine = await db.listAppointmentsByCustomer(req.user.id);
      res.json({
        stats: {
          totalRequests: mine.length,
          pendingAppointments: mine.filter((a) => a.status === 'pending').length,
          confirmedAppointments: mine.filter((a) => a.status === 'confirmed').length,
          cancelledAppointments: mine.filter((a) => a.status === 'cancelled').length,
        },
      });
    })
  );
}

// --- 8E. Stripe Payments & Customer Transactions Routes ---
function registerPaymentRoutes(router) {
  router.post(
    '/payments/create-checkout-session',
    requireAuth,
    requireRole('customer'),
    asyncHandler(async (req, res) => {
      const { appointmentId } = req.body || {};
      if (typeof appointmentId !== 'string' || !appointmentId) {
        res.status(400).json({ error: 'appointmentId is required.' });
        return;
      }

      const apt = await db.findAppointmentById(appointmentId);
      if (!apt) {
        res.status(404).json({ error: 'Appointment not found.' });
        return;
      }
      if (apt.customerId !== req.user.id) {
        res.status(403).json({ error: 'You can only pay for your own appointments.' });
        return;
      }
      if (!canCustomerPayAppointment(apt, req.user.id)) {
        res.status(400).json({ error: 'Only confirmed, unpaid appointments can be paid for.' });
        return;
      }

      const service = await db.findServiceById(apt.serviceId);
      const serviceName = service?.serviceName || apt.serviceName || 'Salon Service Appointment';
      const frontendUrl = resolveRequestOrigin(req);
      const stripe = getStripeClient();
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();

      if (stripe) {
        try {
          const session = await stripe.checkout.sessions.create({
            mode: 'payment',
            customer_email: req.user.email,
            line_items: [
              {
                price_data: {
                  currency: 'usd',
                  product_data: {
                    name: serviceName,
                    description: `Appointment on ${apt.appointmentDate} at ${apt.timeSlot}`,
                  },
                  unit_amount: Math.round(apt.servicePrice * 100),
                },
                quantity: 1,
              },
            ],
            metadata: {
              appointmentId: apt.id,
              customerId: req.user.id,
              amount: String(apt.servicePrice),
            },
            success_url: `${frontendUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}&appointment_id=${apt.id}`,
            cancel_url: `${frontendUrl}/payment/cancel?appointment_id=${apt.id}`,
          });

          await db.createCheckoutSession({
            sessionId: session.id,
            appointmentId: apt.id,
            customerId: req.user.id,
            serviceName,
            amount: apt.servicePrice,
            currency: 'usd',
            mode: 'stripe',
            status: 'pending',
            expiresAt,
            createdAt: new Date().toISOString(),
          });
          await db.updateAppointment(apt.id, { stripeSessionId: session.id });

          res.json({ url: session.url, sessionId: session.id, mode: 'stripe' });
          return;
        } catch (err) {
          const msg = err instanceof Error ? err.message : 'Stripe checkout error';
          res.status(502).json({ error: `Stripe error: ${msg}` });
          return;
        }
      }

      res.status(503).json({
        error:
          'Stripe payments are not configured on this server. Set STRIPE_SECRET_KEY in environment variables to enable secure checkout.',
        code: 'STRIPE_NOT_CONFIGURED',
      });
    })
  );

  router.get(
    '/payments/session/:sessionId',
    requireAuth,
    asyncHandler(async (req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      const sessionId = String(req.params.sessionId);
      let synced;
      try {
        synced = await syncStripeCheckoutSession({
          sessionId,
          expectedCustomerId: req.user.id,
          allowAdmin: req.user.role === 'admin',
        });
      } catch (err) {
        if (err?.statusCode === 403) {
          res.status(403).json({ error: 'Forbidden.' });
          return;
        }
        throw err;
      }

      if (synced.completed && synced.transaction) {
        const apt =
          synced.appointment || (await db.findAppointmentById(synced.transaction.appointmentId));
        const service = apt ? await db.findServiceById(apt.serviceId) : null;
        res.json({
          completed: true,
          transaction: synced.transaction,
          appointment: apt,
          service:
            service ||
            (apt?.serviceName
              ? { id: apt.serviceId, serviceName: apt.serviceName, image: apt.serviceImage || '' }
              : null),
        });
        return;
      }

      if (synced.expired) {
        res.status(410).json({ error: 'Checkout session has expired. Please start payment again.' });
        return;
      }

      const storedSession = synced.session || (await db.findCheckoutSession(sessionId));
      if (storedSession) {
        if (storedSession.customerId !== req.user.id && req.user.role !== 'admin') {
          res.status(403).json({ error: 'Forbidden.' });
          return;
        }
        if (
          storedSession.status === 'expired' ||
          (storedSession.expiresAt && new Date(storedSession.expiresAt).getTime() < Date.now())
        ) {
          await db.markCheckoutSessionStatus(sessionId, 'expired');
          res.status(410).json({ error: 'Checkout session has expired. Please start payment again.' });
          return;
        }
        if (storedSession.status === 'pending') {
          const apt = await db.findAppointmentById(storedSession.appointmentId);
          res.json({ session: storedSession, appointment: apt || null, completed: false });
          return;
        }
      }

      res.status(404).json({ error: 'Checkout session not found or expired.' });
    })
  );



  router.get(
    '/transactions/my',
    requireAuth,
    requireRole('customer'),
    asyncHandler(async (req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      const [mineAppointments, allServices] = await Promise.all([
        db.listAppointmentsByCustomer(req.user.id),
        db.listServices({ includeInactive: true }),
      ]);
      const { appointments: reconciled } = await reconcilePendingStripeAppointments(
        mineAppointments,
        { expectedCustomerId: req.user.id }
      );
      const txns = await db.listTransactionsByCustomer(req.user.id);
      const aptMap = new Map(reconciled.map((a) => [a.id, a]));
      const svcMap = new Map(allServices.map((s) => [s.id, s]));

      const enriched = txns.map((txn) => {
        const apt = aptMap.get(txn.appointmentId) || null;
        const svc = apt ? buildServiceFallback(apt, svcMap) : null;
        return {
          ...txn,
          appointment: apt,
          service: svc,
        };
      });

      const paidTxns = enriched.filter((t) => t.status === 'paid');
      const totalPaid = paidTxns.reduce((sum, t) => sum + Number(t.amount || 0), 0);
      const unpaidConfirmedBalance = reconciled
        .filter((a) => a.status === 'confirmed' && a.paymentStatus !== 'paid')
        .reduce((sum, a) => sum + Number(a.servicePrice || 0), 0);

      res.json({
        transactions: enriched,
        summary: {
          totalPaid,
          completedPayments: paidTxns.length,
          unpaidConfirmedBalance,
        },
      });
    })
  );
}

// --- 8F. Admin Management Routes ---
function registerAdminRoutes(router) {
  router.get(
    '/admin/appointments',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (_req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      const [allAppointments, allServices, allUsers] = await Promise.all([
        db.listAppointments(),
        db.listServices({ includeInactive: true }),
        db.listUsers(),
      ]);
      const { appointments: reconciled } = await reconcilePendingStripeAppointments(
        allAppointments,
        { allowAdmin: true }
      );
      const serviceMap = new Map(allServices.map((s) => [s.id, s]));
      const userMap = new Map(allUsers.map((u) => [u.id, sanitizeUser(u)]));

      res.json({
        appointments: reconciled.map((apt) => ({
          ...apt,
          service: buildServiceFallback(apt, serviceMap),
          customer: userMap.get(apt.customerId) || null,
        })),
      });
    })
  );

  router.patch(
    '/admin/appointments/:id/status',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (req, res) => {
      const id = String(req.params.id);
      const apt = await db.findAppointmentById(id);
      if (!apt) {
        res.status(404).json({ error: 'Appointment not found.' });
        return;
      }

      const { status } = req.body || {};
      if (status === 'confirmed') {
        if (apt.status === 'confirmed') {
          res.json({ appointment: apt, alreadyUpdated: true });
          return;
        }
        if (!canAdminConfirmAppointment(apt)) {
          res.status(400).json({ error: 'Only pending appointments can be confirmed.' });
          return;
        }
      } else if (status === 'cancelled') {
        if (apt.status === 'cancelled') {
          res.json({ appointment: apt, alreadyUpdated: true });
          return;
        }
        if (!canAdminCancelAppointment(apt)) {
          res.status(400).json({ error: 'This appointment cannot be cancelled.' });
          return;
        }
      } else {
        res.status(400).json({ error: 'Invalid status update. Use confirmed or cancelled.' });
        return;
      }

      const updated = await db.updateAppointment(id, { status });
      res.json({ appointment: updated });
    })
  );

  router.get(
    '/admin/users',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (_req, res) => {
      const [allUsers, countMap] = await Promise.all([
        db.listUsers(),
        db.countAppointmentsByCustomerMap(),
      ]);

      const customers = allUsers
        .filter((u) => u.role === 'customer')
        .map((u) => ({
          ...sanitizeUser(u),
          appointmentCount: countMap.get(u.id) || 0,
        }));
      res.json({ users: customers });
    })
  );

  router.patch(
    '/admin/users/:id/block',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (req, res) => {
      const id = String(req.params.id);
      const target = await db.findUserById(id);
      if (!target) {
        res.status(404).json({ error: 'User not found.' });
        return;
      }
      if (target.role === 'admin') {
        res.status(400).json({ error: 'Administrator accounts cannot be blocked.' });
        return;
      }

      const { isBlocked } = req.body || {};
      if (typeof isBlocked !== 'boolean') {
        res.status(400).json({ error: 'isBlocked boolean is required.' });
        return;
      }

      const updated = await db.setUserBlocked(id, isBlocked);
      res.json({ user: updated ? sanitizeUser(updated) : null });
    })
  );

  router.get(
    '/admin/transactions',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (_req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      const [initialTxns, users, allAppointments, services] = await Promise.all([
        db.listTransactions(),
        db.listUsers(),
        db.listAppointments(),
        db.listServices({ includeInactive: true }),
      ]);

      const { appointments, updatedCount } = await reconcilePendingStripeAppointments(
        allAppointments,
        { allowAdmin: true }
      );
      const txns = updatedCount > 0 ? await db.listTransactions() : initialTxns;

      const userMap = new Map(users.map((u) => [u.id, sanitizeUser(u)]));
      const aptMap = new Map(appointments.map((a) => [a.id, a]));
      const svcMap = new Map(services.map((s) => [s.id, s]));

      res.json({
        transactions: txns.map((txn) => {
          const apt = aptMap.get(txn.appointmentId) || null;
          const svc = apt ? buildServiceFallback(apt, svcMap) : null;
          return {
            ...txn,
            customer: userMap.get(txn.customerId) || null,
            appointment: apt,
            service: svc,
          };
        }),
      });
    })
  );

  router.get(
    '/admin/stats',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (_req, res) => {
      const stats = await db.getAdminStats();
      res.json({ stats });
    })
  );

  router.get(
    '/admin/overview',
    requireAuth,
    requireRole('admin'),
    asyncHandler(async (_req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      const [initialStats, allAppointments, allServices, allUsers] = await Promise.all([
        db.getAdminStats(),
        db.listAppointments(),
        db.listServices({ includeInactive: true }),
        db.listUsers(),
      ]);
      const { appointments: reconciled, updatedCount } = await reconcilePendingStripeAppointments(
        allAppointments,
        { allowAdmin: true }
      );
      const stats = updatedCount > 0 ? await db.getAdminStats() : initialStats;
      const serviceMap = new Map(allServices.map((s) => [s.id, s]));
      const userMap = new Map(allUsers.map((u) => [u.id, sanitizeUser(u)]));

      res.json({
        stats,
        appointments: reconciled.map((apt) => ({
          ...apt,
          service: buildServiceFallback(apt, serviceMap),
          customer: userMap.get(apt.customerId) || null,
        })),
      });
    })
  );
}

export function createApiRouter() {
  const router = express.Router();

  router.get(
    '/health',
    asyncHandler(async (_req, res) => {
      const dbHealth = await db.getHealthDetails();
      res.setHeader('Cache-Control', 'no-store');
      res.json({
        ok: true,
        service: 'salonbook-backend',
        ...dbHealth,
        authProvider: 'jwt',
        googleAuthEnabled: isGoogleSocialAuthEnabled(),
        stripeConfigured: Boolean(getStripeSecretKey()),
        imgbbConfigured: Boolean(getImgbbApiKey()),
        timestamp: new Date().toISOString(),
      });
    })
  );

  registerAuthRoutes(router);
  registerUploadRoutes(router);
  registerServiceRoutes(router);
  registerAppointmentRoutes(router);
  registerPaymentRoutes(router);
  registerAdminRoutes(router);

  return router;
}

// ============================================================================
// 9. Express Application, Localhost Bootstrap & Vercel Serverless Handler
// ============================================================================

export function createExpressApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // Lightweight gzip compression for JSON responses >= 1KB
  app.use((req, res, next) => {
    const acceptEncoding = String(req.headers['accept-encoding'] || '');
    if (!acceptEncoding.includes('gzip')) {
      next();
      return;
    }
    const origJson = res.json.bind(res);
    res.json = (body) => {
      try {
        const serialized = JSON.stringify(body);
        if (serialized.length < 1024 || res.headersSent) {
          return origJson(body);
        }
        const compressed = zlib.gzipSync(serialized, { level: zlib.constants.Z_BEST_SPEED });
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.setHeader('Content-Encoding', 'gzip');
        res.setHeader('Vary', 'Accept-Encoding');
        res.setHeader('Content-Length', String(compressed.length));
        return res.send(compressed);
      } catch {
        return origJson(body);
      }
    };
    next();
  });

  // Strict CORS allowlist for browser origins
  const corsOptions = {
    origin(origin, callback) {
      if (isOriginAllowed(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`Origin ${origin} not allowed by CORS`));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'stripe-signature'],
  };

  app.use(cors(corsOptions));
  app.options('*', cors(corsOptions));

  // Ensure MongoDB (Mongoose) or memory repository is initialized
  app.use(async (_req, _res, next) => {
    try {
      await db.init();
      next();
    } catch (err) {
      next(err);
    }
  });

  // Stripe Webhook MUST receive raw Buffer body BEFORE express.json()
  app.post(
    '/api/webhooks/stripe',
    express.raw({ type: 'application/json' }),
    createStripeWebhookHandler()
  );

  // Standard JSON & URL-encoded body parsers
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Serve local fallback uploaded images if ImgBB key is not configured
  app.use('/uploads', express.static(UPLOADS_DIR, { maxAge: '365d', immutable: true }));

  // Root status endpoint
  app.get('/', (_req, res) => {
    res.json({
      name: 'SalonBook REST API',
      stack: [
        'Node.js',
        'Express.js',
        'MongoDB (Mongoose)',
        'REST API',
        'JWT Authentication & Authorization',
        'Stripe',
        'ImgBB',
      ],
      status: 'running',
      database: db.getStorageMode(),
      healthCheck: '/api/health',
    });
  });

  // Mount all REST API endpoints under /api
  app.use('/api', createApiRouter());

  // 404 JSON fallback
  app.use((_req, res) => {
    res.status(404).json({ error: 'Requested API endpoint does not exist.' });
  });

  // Global Express error handler
  app.use((err, _req, res, _next) => {
    console.error('SalonBook Backend Error:', err?.message || err);
    if (err?.message?.includes('CORS')) {
      res.status(403).json({ error: err.message });
      return;
    }
    if (err?.type === 'entity.parse.failed' || (err instanceof SyntaxError && err?.status === 400)) {
      res.status(400).json({ error: 'Invalid JSON request payload.' });
      return;
    }
    const status =
      typeof err?.statusCode === 'number' && err.statusCode >= 400 && err.statusCode < 600
        ? err.statusCode
        : typeof err?.status === 'number' && err.status >= 400 && err.status < 600
          ? err.status
          : 500;
    res.status(status).json({ error: err?.message || 'Internal server error.' });
  });

  return app;
}

const app = createExpressApp();

export async function listenWithRetry(
  expressApp,
  preferredPort,
  {
    host = '0.0.0.0',
    samePortRetries = 2,
    retryDelayMs = 350,
    maxPortOffset = 10,
    strictPort = process.env.STRICT_PORT === 'true',
  } = {}
) {
  const tryBind = (port) =>
    new Promise((resolve, reject) => {
      const server = expressApp.listen(port, host);
      const onError = (err) => {
        server.removeListener('listening', onListening);
        reject(err);
      };
      const onListening = () => {
        server.removeListener('error', onError);
        const addr = server.address();
        const actualPort = typeof addr === 'object' && addr ? addr.port : port;
        resolve({ server, port: actualPort });
      };
      server.once('error', onError);
      server.once('listening', onListening);
    });

  let lastError = null;

  for (let attempt = 0; attempt <= samePortRetries; attempt++) {
    try {
      return await tryBind(preferredPort);
    } catch (err) {
      lastError = err;
      if (err?.code !== 'EADDRINUSE') {
        throw err;
      }
      if (attempt < samePortRetries) {
        await new Promise((r) => setTimeout(r, retryDelayMs));
      }
    }
  }

  if (strictPort || preferredPort === 0) {
    throw lastError;
  }

  for (let offset = 1; offset <= maxPortOffset; offset++) {
    const candidatePort = preferredPort + offset;
    try {
      return await tryBind(candidatePort);
    } catch (err) {
      lastError = err;
      if (err?.code !== 'EADDRINUSE') {
        throw err;
      }
    }
  }

  throw lastError;
}

export async function bootstrap(options = {}) {
  const { onShutdown } = options;
  const preferredPort = getPort();
  const dbInitPromise = db.init().catch((err) => {
    console.error('Database initialization warning:', sanitizeMongoError(err));
    return { mode: 'memory' };
  });

  const { server, port } = await listenWithRetry(app, preferredPort);

  server.keepAliveTimeout = 65000;
  server.headersTimeout = 66000;

  if (port !== preferredPort) {
    console.warn(
      `Port ${preferredPort} is already in use. Switched SalonBook Backend API to http://localhost:${port}.`
    );
  }

  dbInitPromise.then(({ mode }) => {
    console.log(`SalonBook Backend API running on http://localhost:${port} [${mode}]`);
  });

  let shuttingDown = false;
  const gracefulShutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;

    const finishExit = () => {
      if (signal === 'SIGUSR2') {
        process.kill(process.pid, 'SIGUSR2');
      } else {
        process.exit(0);
      }
    };

    const forceTimer = setTimeout(finishExit, 2500);
    forceTimer.unref();

    Promise.resolve()
      .then(async () => {
        if (typeof onShutdown === 'function') {
          await onShutdown(signal);
        }
      })
      .catch(() => {
        // ignore child shutdown errors
      })
      .finally(() => {
        server.close(async () => {
          try {
            if (mongoose.connection.readyState !== 0) {
              await mongoose.connection.close();
            }
          } catch {
            // ignore close errors during shutdown
          }
          clearTimeout(forceTimer);
          finishExit();
        });
      });
  };

  process.once('SIGINT', () => gracefulShutdown('SIGINT'));
  process.once('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.once('SIGUSR2', () => gracefulShutdown('SIGUSR2'));

  return server;
}

// Vercel Serverless Function entry point
export default async function handler(req, res) {
  await db.init();
  return app(req, res);
}

function readCliFlagValue(argv, names) {
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    for (const name of names) {
      if (arg === name && argv[i + 1] && !argv[i + 1].startsWith('-')) {
        return argv[i + 1];
      }
      if (arg.startsWith(`${name}=`)) {
        return arg.slice(name.length + 1);
      }
    }
  }
  return '';
}

function isPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function clearStaleNextDevLock(frontendDir) {
  const lockPath = path.join(frontendDir, '.next', 'dev', 'lock');
  if (!fs.existsSync(lockPath)) return;

  try {
    const raw = fs.readFileSync(lockPath, 'utf8').trim();
    const parsed = raw ? JSON.parse(raw) : null;
    const lockPid = Number(parsed?.pid);

    if (Number.isInteger(lockPid) && lockPid > 0 && lockPid !== process.pid) {
      if (isPidAlive(lockPid)) {
        try {
          process.kill(lockPid, 'SIGTERM');
        } catch {
          // ignore permission/race errors
        }
        for (let i = 0; i < 15; i += 1) {
          if (!isPidAlive(lockPid)) break;
          await new Promise((r) => setTimeout(r, 100));
        }
        if (isPidAlive(lockPid)) {
          try {
            process.kill(lockPid, 'SIGKILL');
          } catch {
            // ignore
          }
          await new Promise((r) => setTimeout(r, 100));
        }
      }
    }
  } catch {
    // Malformed or empty lock file — safe to remove below
  }

  try {
    if (fs.existsSync(lockPath)) {
      fs.unlinkSync(lockPath);
    }
  } catch {
    // ignore unlink errors if already removed
  }
}

function terminateChildProcessTree(child, signal = 'SIGTERM') {
  if (!child || child.killed || child.exitCode !== null) return;
  try {
    if (process.platform !== 'win32' && child.pid) {
      process.kill(-child.pid, signal);
    } else {
      child.kill(signal);
    }
  } catch {
    try {
      child.kill(signal);
    } catch {
      // ignore
    }
  }
}

// Localhost / Node server auto-start
const isMainModule =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isMainModule && !process.env.VERCEL) {
  const withFrontendDev = process.argv.includes('--dev');
  const withFrontendStart = process.argv.includes('--start');

  if (withFrontendDev || withFrontendStart) {
    const backendPort = process.env.BACKEND_PORT || '5000';
    const cliPort = readCliFlagValue(process.argv, ['--port', '-p']);
    const cliHost = readCliFlagValue(process.argv, ['--host', '-H']);
    const frontendPort = cliPort || process.env.FRONTEND_PORT || '3000';
    const frontendHost = cliHost || process.env.FRONTEND_HOST || '0.0.0.0';
    process.env.PORT = backendPort;

    if (withFrontendStart) {
      process.env.NODE_ENV = 'production';
      process.env.SEED_DEMO_DATA = process.env.SEED_DEMO_DATA || 'true';
    }

    const frontendDir = path.resolve(BACKEND_DIR, '../frontend');
    const nextCli = path.join(frontendDir, 'node_modules', 'next', 'dist', 'bin', 'next');
    const nextCmd = withFrontendStart ? 'start' : 'dev';

    let activeFrontendChild = null;
    let isShuttingDown = false;
    let startupAttempts = 0;

    const launchFrontend = async () => {
      if (isShuttingDown) return;
      if (withFrontendDev) {
        await clearStaleNextDevLock(frontendDir);
      }
      if (isShuttingDown) return;

      startupAttempts += 1;
      const startedAt = Date.now();
      const child = spawn(
        process.execPath,
        [nextCli, nextCmd, '-p', frontendPort, '-H', frontendHost],
        {
          cwd: frontendDir,
          stdio: 'inherit',
          detached: process.platform !== 'win32',
          env: {
            ...process.env,
            PORT: frontendPort,
            NODE_ENV: withFrontendStart ? 'production' : 'development',
            BACKEND_URL: process.env.BACKEND_URL || `http://127.0.0.1:${backendPort}`,
            NEXT_PUBLIC_GOOGLE_CLIENT_ID:
              getGoogleClientId() ||
              process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID ||
              '801397027922-te0vr2mpme4oi60g1m6oh8hvmc0tt8q4.apps.googleusercontent.com',
            NEXT_TELEMETRY_DISABLED: '1',
          },
        }
      );
      activeFrontendChild = child;

      child.on('exit', (code) => {
        if (isShuttingDown) return;
        const ranMs = Date.now() - startedAt;
        if (code && code !== 0 && ranMs < 10000 && startupAttempts < 3) {
          console.warn(
            `Next.js ${nextCmd} exited early (code ${code}), retrying startup (${startupAttempts}/3)...`
          );
          setTimeout(() => {
            void launchFrontend();
          }, 600);
          return;
        }
        if (code && code !== 0) {
          process.exit(code);
        }
      });
    };

    const stopFrontendGracefully = async () => {
      isShuttingDown = true;
      const child = activeFrontendChild;
      if (!child || child.exitCode !== null) return;

      await new Promise((resolve) => {
        let settled = false;
        const done = () => {
          if (settled) return;
          settled = true;
          resolve();
        };
        child.once('exit', done);
        terminateChildProcessTree(child, 'SIGTERM');
        setTimeout(() => {
          terminateChildProcessTree(child, 'SIGKILL');
          done();
        }, 1200).unref();
      });
    };

    process.once('exit', () => {
      isShuttingDown = true;
      terminateChildProcessTree(activeFrontendChild, 'SIGTERM');
    });

    bootstrap({ onShutdown: stopFrontendGracefully })
      .then(() => launchFrontend())
      .catch((err) => {
        if (err?.code === 'EADDRINUSE') {
          const port = getPort();
          console.error(
            `Port ${port} is already in use. Close the existing process using port ${port} or set a different PORT in backend/.env.`
          );
          process.exit(1);
        }
        console.error('Failed to bootstrap SalonBook backend:', err);
        process.exit(1);
      });
  } else {
    bootstrap().catch((err) => {
      if (err?.code === 'EADDRINUSE') {
        const port = getPort();
        console.error(
          `Port ${port} is already in use. Close the existing process using port ${port} or set a different PORT in backend/.env.`
        );
        process.exit(1);
      }
      console.error('Failed to bootstrap SalonBook backend:', err);
      process.exit(1);
    });
  }
}
