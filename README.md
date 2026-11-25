# SecureAI

A simplified Next.js website security assessment app. The application performs live, non-intrusive HTTP response checks and calculates a transparent security-configuration score from the observed response.

## Requirements
- Node.js 20.9 or newer (Node 22 LTS or 24 recommended)
- npm

## Run on Windows PowerShell
```powershell
# Extract the ZIP, then enter the extracted folder
cd E:\SecureAI

# Install dependencies
npm install

# Start development server
npm run dev -- --port 3001
```
Open http://localhost:3001.

## Production build
```powershell
npm run typecheck
npm run build
npm run start -- --port 3001
```

## Deploy to Vercel
1. Push this folder to a GitHub repository.
2. Import the repository in Vercel.
3. Framework preset: Next.js. Root directory: `.`. Build command: `npm run build`.
4. Deploy. No environment variables, database, Redis, Celery, Python service or paid API key is required for the included checks.

## Included checks
- HTTP response and status
- HTTPS transport
- HSTS
- Content Security Policy
- Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cookie Secure and HttpOnly attributes when Set-Cookie headers are returned
- Server / X-Powered-By banner exposure

## Important limitations
- The score measures observed HTTP/TLS security configuration only. It is not a malware/phishing verdict, ML prediction, penetration test, or guarantee of safety.
- Checks that cannot be inferred from the response are not represented as successful.
- Scan history is stored in browser localStorage and is not shared across devices.
- Public targets only; private/local addresses are rejected. Only ports 80 and 443 are accepted. Do not scan systems without permission.
- Vercel serverless execution and target-site network policies can affect whether a particular website can be reached.
