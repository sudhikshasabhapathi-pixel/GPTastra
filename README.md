# Kisan Saathi — Full Stack

A runnable full-stack agriculture platform.

## Requirements
- Node.js 18+
- npm

## Start
```bash
npm install
npm start
```
Open **http://localhost:8000**

Development:
```bash
npm run dev
```

## Backend
Express + SQLite (`better-sqlite3`) with APIs for:
- Authentication / registration
- Farmer profile
- Farms
- Crops
- Soil reports
- Weather
- Mandi markets
- Agricultural inputs
- Government schemes
- Alerts
- AI Saathi questions
- Crop-health image upload workflow

The database is automatically created at `data/kisan-saathi.db` and seeded with demo farmer data on first start.

## API examples

Health:
`GET /api/health`

Demo login:
`POST /api/auth/login`
```json
{"phone":"9999999999"}
```

AI:
`POST /api/ai/ask`
```json
{"question":"Should I irrigate my cotton tomorrow?"}
```

Crop-health upload:
`POST /api/crop-health/scan`
multipart form field: `image`

## Production work
The backend is real and persistent, but external services still need credentials/integration:
- SMS/OTP or Google authentication
- Live weather provider
- Live Agmarknet/eNAM/mandi feeds
- Production crop-disease ML model
- Government scheme APIs
- Payment/order provider
- Real expert video/chat scheduling
- Cloud object storage for images
- HTTPS, rate limiting, secure secrets and production monitoring

Never use the seeded demo credentials/data in production.
