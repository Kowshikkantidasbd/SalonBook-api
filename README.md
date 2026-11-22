# SalonBook — Backend REST API

A portable, production-ready Node.js & Express REST API for **SalonBook**, a curated salon and beauty atelier reservation platform. Built with MongoDB (Mongoose), Better Auth, JWT authentication, Stripe verified webhooks, and ImgBB cloud image hosting.

---

## 🌟 Features

- **Authentication & Authorization**:
  - Powered by **Better Auth** (`@better-auth/node`) alongside custom JWT authentication for granular role-based access control (`customer`, `admin`).
  - Google Social Sign-In integration (OAuth 2.0).
  - Password hashing with `bcryptjs`.
  - Administrator user management (blocking/unblocking accounts).
- **Service Catalog Management**:
  - Public catalog browsing with category filtering, search, and price/duration sorting.
  - Admin CRUD endpoints to create, edit, activate/deactivate, and delete salon services.
- **Appointment Scheduling & Conflict Prevention**:
  - Real-time slot conflict prevention ensuring no double-booking for the same service or customer on any given date and time slot.
  - Customer appointment booking, cancellation (for pending bookings), and status tracking.
  - Admin appointment management: approve/confirm, decline, complete, or reschedule bookings.
- **Secure Stripe Payment & Webhooks**:
  - Secure Stripe Checkout Session generation.
  - **Verified Stripe Webhook Processing** (`/api/webhooks/stripe`): Payment status in the database is strictly updated only upon receiving cryptographically verified `checkout.session.completed` events via `stripe.webhooks.constructEvent`.
  - Transaction history tracking and digital receipts.
- **Cloud Image Uploads**:
  - ImgBB API integration with `multer` memory storage for service and profile photo uploads.
- **Health Checks & Observability**:
  - Comprehensive health check endpoint (`/api/health`) reporting database connection state, auth configuration, Stripe status, and image service connectivity.

---

## 🛠️ Tech Stack

- **Runtime**: Node.js (v18+)
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose ODM
- **Authentication**: Better Auth (`better-auth`) + JWT (`jsonwebtoken`) + `bcryptjs`
- **Payments**: Stripe (`stripe`) with cryptographic webhook verification
- **File Uploads**: Multer + ImgBB API
- **Deployment**: Compatible with Vercel Serverless Functions, Render, Railway, or standalone Node.js environments.

---

## 📋 Environment Variables

Create a `.env` file inside the `Backend/` directory. **Do not commit secret keys to version control.**

| Variable Name | Required | Description |
|---|---|---|
| `PORT` | Optional | Port for the Express server (default: `5000`) |
| `NODE_ENV` | Optional | Environment mode (`development` or `production`) |
| `MONGODB_URI` | **Yes** | MongoDB connection string (e.g. MongoDB Atlas cluster URI) |
| `MONGODB_DB_NAME` | Optional | Database name (default: `salonbook`) |
| `JWT_SECRET` | **Yes** (in production) | Cryptographic secret for signing JWT tokens |
| `BETTER_AUTH_URL` | Optional | Public URL of the backend for Better Auth callbacks |
| `FRONTEND_URL` | **Yes** | Allowed frontend URL for CORS (e.g. `https://salonbook.vercel.app` or `http://localhost:3000`) |
| `BACKEND_PUBLIC_URL` | Optional | Public URL of this backend API for redirects and webhooks |
| `STRIPE_SECRET_KEY` | **Yes** | Stripe secret API key (`sk_live_...` or `sk_test_...`) |
| `STRIPE_WEBHOOK_SECRET` | **Yes** | Stripe endpoint webhook signing secret (`whsec_...`) |
| `IMGBB_API_KEY` | **Yes** (in production) | API key from ImgBB for hosting uploaded images |
| `GOOGLE_CLIENT_ID` | Optional | Google OAuth 2.0 Client ID for Google Sign-In |
| `GOOGLE_CLIENT_SECRET` | Optional | Google OAuth 2.0 Client Secret |
| `ADMIN_EMAIL` | Optional | Default administrator email seeded on first run |
| `ADMIN_PASSWORD` | Optional | Default administrator password seeded on first run |
| `SEED_DEMO_DATA` | Optional | Set to `false` in production (default: `false` when `NODE_ENV=production`) |

---

## 🚀 Getting Started

### 1. Installation
```bash
cd Backend
npm install
```

### 2. Run in Development Mode
```bash
npm run dev
```
The server will start on `http://127.0.0.1:5000` (or your configured `PORT`) with automatic restart on file change.

### 3. Run Syntax Check & Unit Tests
```bash
npm run build   # Syntax validation
npm test        # Unit verification test suite
```

---

## 🔗 Repository & Live Deployment Links

- **Server Repository**: [GitHub — SalonBook API](https://github.com/Kowshikkantidasbd/SalonBook-api)
- **Client Repository**: [GitHub — SalonBook](https://github.com/Kowshikkantidasbd/SalonBook)
- **Live Backend API**: `https://<your-backend-deployment>.vercel.app`
- **Live Frontend Application**: `https://<your-frontend-deployment>.vercel.app`
