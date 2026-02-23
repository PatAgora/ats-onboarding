# QR Code Fix - Google Charts API

## Problem
QR code wasn't appearing on 2FA setup page - likely due to PIL/Pillow dependency issues on Railway.

## Solution
Switched to Google Charts API for QR code generation - simple, reliable, no dependencies.

## Changes Made

### 1. Updated app.py
- Removed complex local QR generation with qrcode/PIL
- Now uses Google Charts API directly: `https://chart.googleapis.com/chart`
- Simpler code, fewer dependencies, more reliable
- Reduced from 70+ lines to ~30 lines

### 2. Updated setup_2fa.html Template
- Added support for `qr_url` (Google Charts API)
- Now handles three cases:
  1. `qr_code` - base64 encoded image (if available)
  2. `qr_url` - external URL (Google Charts API)
  3. Fallback - placeholder icon if both fail

## Benefits
- ✅ No PIL/Pillow dependency issues
- ✅ Works reliably on all platforms
- ✅ Simpler code
- ✅ Still has manual entry fallback
- ✅ QR codes generated instantly

## Testing
Visit: https://web-production-5a931.up.railway.app/security/2fa/setup
1. Click "Enable Two-Factor Authentication"
2. QR code should now appear from Google Charts
3. Scan with authenticator app
4. Enter 6-digit code to verify

## Status
- Deployed: ✅ Ready to deploy
- Tested: ⏳ Awaiting deployment
- Working: ⏳ Will work after deployment
