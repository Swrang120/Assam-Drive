# Assam Drive

A runnable mobile-first Assam ride-booking foundation.

## Current testable flow
- Customer / Driver / Admin role views
- Bike, Auto and Car selection
- Fare calculation with configurable admin rates
- Verified-driver online/offline gate
- Ride request and driver acceptance
- 4-digit ride OTP with maximum 2 attempts
- Wrong OTP on second attempt cancels the ride
- Ride start/completion and driver earnings
- Ride history
- Browser geolocation permission test
- SOS event UI
- Local persistence with reset
- PWA manifest + service worker

## Important
This commit is the runnable foundation, not a production transport platform. It intentionally does **not** pretend that localStorage is secure or that demo verification/payment/SOS are real.

Production next steps are backend auth, database/RLS, real OTP provider, maps/routing, server-side ride state transitions, real-time driver presence/location, payment verification, document storage/OCR checks, admin authentication, audit logs, and legal/compliance configuration for Assam.

Open `index.html` directly or serve the repository with any static web server.