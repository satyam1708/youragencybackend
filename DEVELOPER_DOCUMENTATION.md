📘 Secure Auth API Documentation
Base URL: http://localhost:5000
💡 This is a secure two-step login system using email-password and OTP verification. Tokens are stored in cookies for secure session management.
🔐 Authentication Routes
1. Register a New User
URL: /auth/register
Method: POST
Description: Registers a user with email and password.
Request Body:
{
  "email": "user@example.com",
  "password": "yourSecurePassword"
}
Responses:
201 Created: User registered successfully
409 Conflict: User already exists
2. Login – Step 1 (Email & Password)
URL: /auth/login
Method: POST
Description: Validates email & password. If correct, sends OTP to email.
Request Body:
{
  "email": "user@example.com",
  "password": "yourSecurePassword"
}
Responses:
200 OK: OTP sent to email
401 Unauthorized: Incorrect password
404 Not Found: User does not exist
Frontend should now navigate to the OTP input screen.
3. Login – Step 2 (OTP Verification)
URL: /auth/verify-otp
Method: POST
Description: Verifies OTP and logs user in by setting secure cookies.
Request Body:
{
  "email": "user@example.com",
  "otp": "123456"
}
Responses:
200 OK: Logged in successfully (cookies set: accessToken, refreshToken)
401 Unauthorized: OTP invalid or not generated
Frontend must send this request immediately after login step 1. The cookies are HTTP-only, so no need to manually handle tokens on the frontend.
4. Refresh Access Token
URL: /auth/refresh-token
Method: POST
Description: Refreshes the access token using the refresh token cookie.
Request Headers: Cookies must include refreshToken.
Responses:
200 OK: New access token set as cookie
401 Unauthorized: No token found
403 Forbidden: Invalid or expired token
Used to keep the user session alive without logging in again.
5. Logout
URL: /auth/logout
Method: POST
Description: Clears both access and refresh token cookies.
Responses:
200 OK: Logged out successfully
🍪 Cookies Used
Cookie Name	Type	Expires In	Purpose
accessToken	HTTP-only	15 minutes	Authenticated API access
refreshToken	HTTP-only	7 days	Session persistence
✅ All cookies are HttpOnly, Secure, and SameSite=Strict.
⚠️ Security & Limitations
Rate limiting: Max 100 requests per 15 minutes per IP
OTP expires in 5 minutes (handled client-side)
In-memory storage (for demo): Replace with DB (e.g., PostgreSQL, MongoDB) in production
📦 Technologies Used
Express.js – Server framework
bcrypt – Password & OTP hashing
jsonwebtoken – Token creation and verification
Resend API – Email delivery (https://resend.com)
Cookies – Secure session management
Rate Limiting – Prevent brute force attacks
🔧 Frontend Developer Checklist
Login flow:
Send credentials to /auth/login
Show OTP screen after successful response
Send OTP to /auth/verify-otp
Use withCredentials: true in all fetch/axios calls
Use cookie-based authentication (no need to store JWT manually)
Call /auth/refresh-token periodically (e.g., every 10 minutes or on 401)
Handle /auth/logout for signout















Backend API Documentation for Auth Service

Base URL:
http://localhost:5000
1. Register User
Route: /auth/register
Method: POST
Purpose: Register a new user with email and password.
Request Body:
{
  "email": "user@example.com",
  "password": "StrongPassw0rd!"
}
Response:
201 Created with message and CSRF token
Errors: validation errors, user exists, weak password
Notes: Password must be strong (uppercase, lowercase, number, special char). Returns new CSRF token.
2. Login - Stage 1 (Credentials & OTP generation)
Route: /auth/login
Method: POST
Purpose: Validate user credentials, generate & send OTP via email.
Request Body:
{
  "email": "user@example.com",
  "password": "UserPassword"
}
Response:
200 OK with message and CSRF token
Errors: invalid credentials, user not found
Notes: OTP sent to user email, expires in 5 minutes.
3. Login - Stage 2 (OTP verification)
Route: /auth/verify-otp
Method: POST
Purpose: Verify the OTP sent to email and login the user.
Request Body:
{
  "email": "user@example.com",
  "otp": "123456"
}
Response:
200 OK with message, CSRF token, and sets accessToken and refreshToken cookies
Errors: invalid/expired OTP, too many attempts (rate limited)
Notes: Sets httpOnly cookies for auth tokens.
4. Refresh Access Token
Route: /auth/refresh-token
Method: POST
Purpose: Generate new access token using refresh token cookie.
Request: No body, requires refreshToken cookie.
Response:
200 OK with message and new accessToken cookie
Errors: missing or invalid refresh token (403/401)
5. Logout
Route: /auth/logout
Method: POST
Purpose: Logs out user by deleting refresh tokens and clearing cookies.
Request: No body, requires refreshToken cookie.
Response:
200 OK with logout message
Errors: server error
Notes: Clears accessToken and refreshToken cookies.
6. Get Logged-in User Info
Route: /auth/me
Method: GET
Purpose: Return logged-in user info from access token cookie.
Request: Requires accessToken cookie.
Response:
{
  "email": "user@example.com",
  "type": "NORMAL"
}
Errors: 401 if not logged in, 403 if invalid token.
7. Delete User (Right to Erasure)
Route: /auth/delete
Method: POST
Purpose: Delete user and related refresh tokens.
Request Body:
{
  "email": "user@example.com"
}
Response:
200 OK with confirmation message
Errors: user not found, server error
Notes: Clears auth cookies on success.
8. Get CSRF Token
Route: /csrf-token
Method: GET
Purpose: Returns a fresh CSRF token.
Response:
{
  "csrfToken": "token_string_here"
}
Use: Frontend can use this token for protected POST requests.
9. Get Privacy Policy URL
Route: /privacy-policy
Method: GET
Purpose: Provides URL to privacy policy page.
Response:
{
  "url": "https://yourdomain.com/privacy-policy"
}
Important Notes for Frontend Integration

All POST routes expect CSRF tokens in headers/cookies (use /csrf-token endpoint to fetch fresh token).
Authentication tokens are stored in httpOnly cookies: accessToken (short-lived) and refreshToken (long-lived).
On login success, cookies are set automatically via backend response.
Use accessToken cookie for authenticated GET requests like /auth/me.
Rate limiting applied on OTP verification to prevent brute-force attacks.
Password strength and validation happen on backend; frontend can add similar validation for better UX.