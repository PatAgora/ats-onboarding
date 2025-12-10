"""
Security integration for existing app.py
This file contains the security enhancements to be integrated into app.py
"""

# Add these imports at the top of app.py (after existing imports):
SECURITY_IMPORTS = """
# Security enhancements - CREST compliance
from security import (
    init_security, audit_log, require_mfa,
    generate_mfa_secret, generate_mfa_qr_code, verify_mfa_token,
    generate_magic_link_token, verify_magic_link_token,
    validate_file_upload, sanitize_filename,
    validate_password_strength, add_security_headers
)
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
"""

# Add after app initialization (after line 205: app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)):
SECURITY_INITIALIZATION = """
# Initialize Sentry for error monitoring (optional but recommended)
sentry_dsn = os.getenv('SENTRY_DSN')
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.1,  # 10% of transactions for performance monitoring
        environment=os.getenv('FLASK_ENV', 'production'),
    )

# Initialize security middleware
limiter = init_security(app)

# Apply rate limiting to authentication routes
@limiter.limit("5 per minute")
def rate_limit_auth():
    pass

# Add security headers to all responses
@app.after_request
def after_request(response):
    return add_security_headers(response)
"""

# Add these new routes for MFA setup (insert before the existing login routes):
MFA_ROUTES = '''
# --- MFA/2FA Routes for Admin Users ---

@app.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    """Setup MFA for current admin user."""
    from app import engine, text
    
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        secret = session.get("mfa_setup_secret")
        
        if not secret:
            flash("MFA setup session expired. Please try again.", "danger")
            return redirect(url_for("mfa_setup"))
        
        if verify_mfa_token(secret, token):
            # Save MFA secret to user record
            with Session(engine) as s:
                s.execute(
                    text("UPDATE users SET mfa_secret = :secret WHERE id = :user_id"),
                    {"secret": secret, "user_id": current_user.id}
                )
                s.commit()
            
            session.pop("mfa_setup_secret", None)
            session["mfa_verified"] = True
            
            audit_log("mfa_enabled", user_id=current_user.id)
            flash("MFA enabled successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid verification code. Please try again.", "danger")
    
    # Generate new secret for setup
    secret = generate_mfa_secret()
    session["mfa_setup_secret"] = secret
    
    # Generate QR code
    qr_code = generate_mfa_qr_code(secret, current_user.email)
    
    return render_template("mfa_setup.html", qr_code=qr_code, secret=secret)


@app.route("/mfa/verify", methods=["GET", "POST"])
@login_required
def mfa_verify():
    """Verify MFA token for admin user."""
    from app import engine, text
    
    # Check if user has MFA enabled
    with Session(engine) as s:
        row = s.execute(
            text("SELECT mfa_secret FROM users WHERE id = :user_id"),
            {"user_id": current_user.id}
        ).first()
        
        if not row or not row[0]:
            # MFA not set up, redirect to setup
            return redirect(url_for("mfa_setup"))
        
        mfa_secret = row[0]
    
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        
        if verify_mfa_token(mfa_secret, token):
            session["mfa_verified"] = True
            session.permanent = True  # Make session persistent
            
            audit_log("mfa_verified", user_id=current_user.id)
            
            next_url = request.args.get("next") or url_for("dashboard")
            return redirect(next_url)
        else:
            audit_log("mfa_verification_failed", user_id=current_user.id)
            flash("Invalid verification code. Please try again.", "danger")
    
    return render_template("mfa_verify.html")


@app.route("/mfa/disable", methods=["POST"])
@login_required
@require_mfa
def mfa_disable():
    """Disable MFA for current user (requires MFA verification)."""
    from app import engine, text
    
    with Session(engine) as s:
        s.execute(
            text("UPDATE users SET mfa_secret = NULL WHERE id = :user_id"),
            {"user_id": current_user.id}
        )
        s.commit()
    
    session.pop("mfa_verified", None)
    audit_log("mfa_disabled", user_id=current_user.id)
    
    flash("MFA disabled.", "info")
    return redirect(url_for("dashboard"))
'''

# Add these routes for magic link authentication (for candidates):
MAGIC_LINK_ROUTES = '''
# --- Magic Link Authentication for Candidates ---

@app.route("/candidate/send-magic-link", methods=["POST"])
@limiter.limit("3 per minute")
def send_candidate_magic_link():
    """Send magic link to candidate email."""
    from app import engine, Candidate
    
    email = request.form.get("email", "").strip().lower()
    
    if not email:
        flash("Please provide your email address.", "danger")
        return redirect(url_for("public.login"))
    
    with Session(engine) as s:
        candidate = s.query(Candidate).filter(Candidate.email.ilike(email)).first()
        
        if not candidate:
            # Create new candidate
            candidate = Candidate(
                email=email,
                name=email.split("@")[0]
            )
            s.add(candidate)
            s.commit()
            s.refresh(candidate)
        
        # Generate magic link token
        token = generate_magic_link_token(candidate.id, candidate.email)
        magic_link = url_for("candidate_magic_login", token=token, _external=True)
        
        # Send email (implement your email sending logic)
        try:
            send_magic_link_email(candidate.email, magic_link)
            audit_log("magic_link_sent", user_id=candidate.id, details={"email": email})
            flash("Check your email for the sign-in link!", "success")
        except Exception as e:
            current_app.logger.error(f"Failed to send magic link: {e}")
            flash("Failed to send email. Please try again.", "danger")
    
    return redirect(url_for("public.login"))


@app.route("/candidate/login/<token>")
def candidate_magic_login(token):
    """Authenticate candidate using magic link token."""
    from app import engine, Candidate
    
    candidate_id, email = verify_magic_link_token(token, max_age=3600)  # 1 hour expiry
    
    if not candidate_id:
        audit_log("magic_link_invalid", details={"token": token[:10]})
        flash("Invalid or expired login link.", "danger")
        return redirect(url_for("public.login"))
    
    with Session(engine) as s:
        candidate = s.get(Candidate, candidate_id)
        
        if not candidate or candidate.email.lower() != email.lower():
            audit_log("magic_link_mismatch", user_id=candidate_id)
            flash("Invalid login link.", "danger")
            return redirect(url_for("public.login"))
        
        # Set session
        session["public_user_id"] = candidate.id
        session.permanent = True
        
        audit_log("candidate_login_magic_link", user_id=candidate.id)
        flash(f"Welcome back, {candidate.name}!", "success")
    
    return redirect(url_for("public.jobs_index"))


def send_magic_link_email(to_email, magic_link):
    """
    Send magic link email to candidate.
    Uses existing SMTP configuration.
    """
    if not SMTP_HOST or not SMTP_USER:
        current_app.logger.warning("SMTP not configured, skipping magic link email")
        return
    
    msg = EmailMessage()
    msg["Subject"] = "Your secure sign-in link"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    
    msg.set_content(f"""
    Hi,
    
    Click the link below to sign in to your account:
    
    {magic_link}
    
    This link will expire in 1 hour.
    
    If you didn't request this, please ignore this email.
    
    Best regards,
    The Talent Team
    """)
    
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    except Exception as e:
        current_app.logger.error(f"SMTP error: {e}")
        raise
'''

# Database migration for MFA column:
DATABASE_MIGRATION = """
-- Add MFA support to users table
-- Run this SQL on your database after deployment

ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled_at TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_users_mfa ON users(mfa_secret) WHERE mfa_secret IS NOT NULL;

-- Add audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    user_id INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    INDEX idx_audit_timestamp (timestamp),
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_event (event_type)
);
"""

print("""
===========================================
SECURITY INTEGRATION INSTRUCTIONS
===========================================

1. Add SECURITY_IMPORTS to the top of app.py (after existing imports)

2. Add SECURITY_INITIALIZATION after app configuration (around line 205)

3. Add MFA_ROUTES before existing login routes (around line 6200)

4. Add MAGIC_LINK_ROUTES after MFA routes

5. Run DATABASE_MIGRATION SQL on your database

6. Update existing @login_required routes to use @require_mfa for sensitive operations

7. Update file upload handlers to use validate_file_upload()

8. Test all authentication flows before deployment
===========================================
""")
