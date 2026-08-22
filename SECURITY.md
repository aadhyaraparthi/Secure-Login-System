# Security Notes

## Implemented

- Passwords are hashed with Werkzeug's password hashing utilities; plaintext passwords are never stored.
- SQL statements use parameter binding (`?`) rather than string concatenation.
- POST forms use Flask-WTF CSRF tokens.
- Session cookies are HttpOnly and SameSite=Lax; Secure can be enabled with `COOKIE_SECURE=1` when using HTTPS.
- Login attempts are temporarily locked after repeated failures.
- Authentication errors use a generic message to avoid obvious username enumeration.
- Input is constrained with server-side validation.

## Production hardening

Before deploying publicly:

1. Use HTTPS everywhere.
2. Set a long random `SECRET_KEY` through a secret manager/environment variable.
3. Set `COOKIE_SECURE=1`.
4. Put the application behind a production WSGI server/reverse proxy.
5. Use a production database and encrypted backups.
6. Add rate limiting at the application and/or reverse-proxy layer.
7. Consider MFA/2FA using a well-tested library or identity provider.
8. Add security headers such as CSP, HSTS, X-Content-Type-Options, and a suitable Referrer-Policy.
9. Monitor authentication failures and unusual activity.
10. Keep dependencies updated and run security testing before production use.
