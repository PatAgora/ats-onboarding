# CREST Option C: Full Security Implementation Plan

## Overview
Complete CREST-compliant security implementation for production readiness and penetration testing.

**Timeline:** 1-2 weeks  
**Effort:** ~60-80 hours  
**Phases:** 12 tasks organized into 4 implementation stages

---

## Implementation Strategy

### Stage 1: Critical Security (Days 1-3) - HIGH PRIORITY
Re-enable authentication and add core security features

### Stage 2: Advanced Security (Days 4-7) - HIGH PRIORITY  
Audit logging, file security, password policies

### Stage 3: Enhanced Features (Days 8-10) - MEDIUM PRIORITY
2FA, password reset, session management

### Stage 4: Testing & Documentation (Days 11-14) - CRITICAL
Comprehensive testing, documentation, CREST preparation

---

## Stage 1: Critical Security (Days 1-3)

### Task 1: Re-enable Authentication ✅ READY TO DEPLOY
**Priority:** 🔴 CRITICAL  
**Time:** 30 minutes  
**Risk:** LOW

**What:**
- Uncomment all `@login_required` decorators on staff routes
- Verify admin login works
- Test all protected routes require authentication

**Files to modify:**
- `app.py` - Find and uncomment `# @login_required` comments

**Implementation:**
```python
# Find all instances of:
# @login_required  # TEMPORARILY DISABLED FOR TROUBLESHOOTING

# Replace with:
@login_required
```

**Testing:**
1. Try accessing `/` without login → should redirect to `/login`
2. Login with admin@os1.com
3. Verify dashboard loads
4. Verify candidate portal (`/apply/*`) still works without login

---

### Task 2: Account Lockout System
**Priority:** 🔴 HIGH  
**Time:** 3-4 hours  
**Risk:** MEDIUM

**What:**
- Track failed login attempts per user
- Lock account after 5 failed attempts
- 30-minute lockout period
- Admin can manually unlock accounts

**Database Changes:**
```sql
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TIMESTAMP NULL;
ALTER TABLE users ADD COLUMN last_failed_login TIMESTAMP NULL;
```

**Implementation:**
```python
# In login route
user = get_user_by_email(email)

if user.locked_until and user.locked_until > datetime.utcnow():
    flash(f"Account locked until {user.locked_until.strftime('%H:%M')}. Try again later.", "error")
    return render_template("login.html")

if not check_password_hash(user.password_hash, password):
    user.failed_login_attempts += 1
    user.last_failed_login = datetime.utcnow()
    
    if user.failed_login_attempts >= 5:
        user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        flash("Too many failed attempts. Account locked for 30 minutes.", "error")
    else:
        remaining = 5 - user.failed_login_attempts
        flash(f"Invalid password. {remaining} attempts remaining.", "error")
    
    db.session.commit()
    return render_template("login.html")

# Successful login - reset counters
user.failed_login_attempts = 0
user.locked_until = None
```

**Admin unlock route:**
```python
@app.route("/admin/unlock-user/<int:user_id>", methods=["POST"])
@login_required
def unlock_user(user_id):
    if current_user.role not in ['admin', 'super_admin']:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()
    
    flash(f"User {user.email} unlocked successfully.", "success")
    return redirect(url_for('admin_list_users'))
```

---

### Task 3: Password Complexity Requirements
**Priority:** 🔴 HIGH  
**Time:** 2 hours  
**Risk:** LOW

**What:**
- Minimum 12 characters (increased from 8)
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 number
- At least 1 special character
- Cannot contain username/email
- Password strength meter on UI

**Implementation:**
```python
import re

def validate_password_strength(password, email=None):
    """
    Returns (is_valid, error_message, strength_score)
    """
    errors = []
    score = 0
    
    if len(password) < 12:
        errors.append("at least 12 characters")
    else:
        score += 1
    
    if not re.search(r'[A-Z]', password):
        errors.append("an uppercase letter")
    else:
        score += 1
    
    if not re.search(r'[a-z]', password):
        errors.append("a lowercase letter")
    else:
        score += 1
    
    if not re.search(r'\d', password):
        errors.append("a number")
    else:
        score += 1
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("a special character")
    else:
        score += 1
    
    if email and email.split('@')[0].lower() in password.lower():
        errors.append("cannot contain your email username")
        score = 0
    
    if errors:
        return False, f"Password must contain {', '.join(errors)}", score
    
    return True, "Strong password", score

# In change_password route:
is_valid, message, score = validate_password_strength(new_password, current_user.email)
if not is_valid:
    flash(message, "error")
    return render_template("change_password.html")
```

**UI Enhancement:**
```html
<!-- In change_password.html -->
<div class="password-strength-meter">
    <div class="strength-bar" id="strength-bar"></div>
    <span id="strength-text"></span>
</div>

<script>
document.getElementById('new_password').addEventListener('input', function(e) {
    const password = e.target.value;
    let score = 0;
    
    if (password.length >= 12) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[!@#$%^&*()]/.test(password)) score++;
    
    const bar = document.getElementById('strength-bar');
    const text = document.getElementById('strength-text');
    
    if (score < 2) {
        bar.style.width = '20%';
        bar.style.backgroundColor = 'red';
        text.textContent = 'Weak';
    } else if (score < 4) {
        bar.style.width = '50%';
        bar.style.backgroundColor = 'orange';
        text.textContent = 'Medium';
    } else {
        bar.style.width = '100%';
        bar.style.backgroundColor = 'green';
        text.textContent = 'Strong';
    }
});
</script>
```

---

### Task 4: Session Timeout (30 Minutes Idle)
**Priority:** 🔴 HIGH  
**Time:** 1-2 hours  
**Risk:** LOW

**What:**
- Automatic logout after 30 minutes of inactivity
- "Remember Me" option for 30-day sessions
- Warning before timeout
- Session activity tracking

**Implementation:**
```python
# In app.py configuration
from datetime import timedelta

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# In login route
if form.remember_me.data:
    login_user(user, remember=True, duration=timedelta(days=30))
else:
    login_user(user, remember=False)
    session.permanent = True  # Use PERMANENT_SESSION_LIFETIME

# Add to base.html template
<script>
let idleTime = 0;
const idleInterval = setInterval(timerIncrement, 60000); // 1 minute

// Reset timer on user activity
document.onclick = () => idleTime = 0;
document.onkeypress = () => idleTime = 0;
document.onmousemove = () => idleTime = 0;

function timerIncrement() {
    idleTime++;
    if (idleTime >= 28) { // 28 minutes - warn before timeout
        alert('Your session will expire in 2 minutes due to inactivity.');
    }
    if (idleTime >= 30) {
        window.location.href = '/logout?reason=timeout';
    }
}
</script>
```

**Add Remember Me checkbox to login form:**
```python
# In LoginForm
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me (30 days)")
    submit = SubmitField("Sign In")
```

---

## Stage 2: Advanced Security (Days 4-7)

### Task 5: Comprehensive Audit Logging
**Priority:** 🔴 HIGH  
**Time:** 6-8 hours  
**Risk:** LOW

**What:**
- Log all authentication events
- Log all admin actions
- Log security events (failed logins, lockouts)
- Log data access (view candidate, export data)
- Searchable audit log UI
- Log retention policy (90 days)

**Database:**
```python
class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    user_email = Column(String(255), nullable=True)
    event_type = Column(String(50), nullable=False, index=True)  # login, logout, create, update, delete, view, export
    event_category = Column(String(50), nullable=False, index=True)  # auth, user_mgmt, data_access, security
    resource_type = Column(String(50), nullable=True)  # candidate, job, engagement, user
    resource_id = Column(Integer, nullable=True)
    action = Column(String(255), nullable=False)
    details = Column(Text, nullable=True)  # JSON string with additional info
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    status = Column(String(20), nullable=False)  # success, failure, warning
    
    user = relationship("User", back_populates="audit_logs")
```

**Logging Helper:**
```python
def log_audit_event(event_type, event_category, action, resource_type=None, resource_id=None, 
                    details=None, status='success'):
    """
    Log an audit event
    
    Example:
        log_audit_event('login', 'auth', 'User logged in', status='success')
        log_audit_event('create', 'user_mgmt', 'Created new user', 'user', new_user.id)
        log_audit_event('view', 'data_access', 'Viewed candidate profile', 'candidate', cand_id)
    """
    log = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        user_email=current_user.email if current_user.is_authenticated else None,
        event_type=event_type,
        event_category=event_category,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        details=json.dumps(details) if details else None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        status=status
    )
    
    with Session(engine) as s:
        s.add(log)
        s.commit()
```

**Usage Examples:**
```python
# In login route
if user and check_password_hash(user.password_hash, password):
    login_user(user)
    log_audit_event('login', 'auth', f'User {user.email} logged in successfully')
else:
    log_audit_event('login', 'auth', f'Failed login attempt for {email}', status='failure')

# In create user route
new_user = User(...)
s.add(new_user)
s.commit()
log_audit_event('create', 'user_mgmt', f'Created user {new_user.email}', 'user', new_user.id)

# In candidate view
log_audit_event('view', 'data_access', f'Viewed candidate profile', 'candidate', cand_id)
```

**Audit Log UI:**
```python
@app.route("/admin/audit-logs")
@login_required
def audit_logs():
    if current_user.role not in ['admin', 'super_admin']:
        abort(403)
    
    page = request.args.get('page', 1, type=int)
    event_type = request.args.get('event_type', '')
    user_email = request.args.get('user_email', '')
    
    with Session(engine) as s:
        query = select(AuditLog).order_by(AuditLog.timestamp.desc())
        
        if event_type:
            query = query.where(AuditLog.event_type == event_type)
        if user_email:
            query = query.where(AuditLog.user_email.ilike(f'%{user_email}%'))
        
        logs = s.scalars(query.limit(50).offset((page-1)*50)).all()
        total = s.scalar(select(func.count()).select_from(AuditLog))
        
        return render_template("admin_audit_logs.html", logs=logs, total=total, page=page)
```

---

### Task 6: File Upload Validation
**Priority:** 🔴 HIGH  
**Time:** 4-5 hours  
**Risk:** MEDIUM

**What:**
- Validate file types (PDF, DOC, DOCX only)
- Validate file size (max 10MB)
- Scan file content for malicious code
- Verify MIME type matches extension
- Sanitize filenames
- Store files securely

**Implementation:**
```python
import magic  # python-magic library

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_upload(file):
    """
    Returns (is_valid, error_message)
    """
    if not file:
        return False, "No file provided"
    
    if file.filename == '':
        return False, "No file selected"
    
    # Check extension
    if not allowed_file(file.filename):
        return False, f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
    
    # Check file size
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Reset to beginning
    
    if file_size > MAX_FILE_SIZE:
        return False, f"File too large. Maximum size: 10MB"
    
    if file_size == 0:
        return False, "File is empty"
    
    # Verify MIME type
    try:
        mime = magic.from_buffer(file.read(2048), mime=True)
        file.seek(0)
        
        allowed_mimes = {
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }
        
        if mime not in allowed_mimes:
            return False, f"Invalid file content. Detected type: {mime}"
    except Exception as e:
        return False, f"Could not verify file type: {str(e)}"
    
    # Check for executable content (basic check)
    file.seek(0)
    first_bytes = file.read(4)
    file.seek(0)
    
    # Check for common executable signatures
    if first_bytes[:2] == b'MZ':  # Windows executable
        return False, "Executable files are not allowed"
    if first_bytes == b'\x7fELF':  # Linux executable
        return False, "Executable files are not allowed"
    
    return True, "File is valid"

# In apply route
cv_file = request.files.get("cv")
is_valid, error_msg = validate_file_upload(cv_file)

if not is_valid:
    flash(error_msg, "danger")
    log_audit_event('upload', 'security', f'Rejected file upload: {error_msg}', status='warning')
    return render_template("apply.html", form=form, job=job)

# Log successful upload
log_audit_event('upload', 'data_access', f'CV uploaded for job {job.id}', 'document', doc.id)
```

**Add to requirements.txt:**
```
python-magic==0.4.27
```

---

### Task 7: Force Password Change on First Login
**Priority:** 🟡 MEDIUM  
**Time:** 2 hours  
**Risk:** LOW

**What:**
- Mark new users as requiring password change
- Redirect to change password page on first login
- Cannot access other pages until password changed
- Admin-created users must change password

**Database:**
```sql
ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP NULL;
```

**Implementation:**
```python
# In User model
must_change_password = Column(Boolean, default=False)
password_changed_at = Column(DateTime, nullable=True)

# In admin create user
new_user.must_change_password = True

# Add middleware
@app.before_request
def check_password_change_required():
    if current_user.is_authenticated and current_user.must_change_password:
        # Allow only logout and change password
        if request.endpoint not in ['change_password', 'logout', 'static']:
            flash("You must change your password before accessing the system.", "warning")
            return redirect(url_for('change_password'))

# In change_password route
user.must_change_password = False
user.password_changed_at = datetime.utcnow()
```

---

## Stage 3: Enhanced Features (Days 8-10)

### Task 8: Two-Factor Authentication (2FA)
**Priority:** 🟡 MEDIUM  
**Time:** 6-8 hours  
**Risk:** MEDIUM

**What:**
- TOTP (Time-based One-Time Password) using authenticator apps
- QR code generation for setup
- Backup codes in case of lost device
- Optional for employees, mandatory for admins
- Grace period for setup

**Dependencies:**
```
pyotp==2.9.0
qrcode==7.4.2
```

**Database:**
```python
class User(Base):
    # ... existing fields ...
    totp_secret = Column(String(32), nullable=True)
    totp_enabled = Column(Boolean, default=False)
    backup_codes = Column(Text, nullable=True)  # JSON array of hashed codes
    totp_enabled_at = Column(DateTime, nullable=True)
```

**Implementation:**
```python
import pyotp
import qrcode
import io
import base64

@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if request.method == "POST":
        token = request.form.get("token")
        
        # Verify token
        totp = pyotp.TOTP(session.get('temp_totp_secret'))
        if totp.verify(token):
            current_user.totp_secret = session.get('temp_totp_secret')
            current_user.totp_enabled = True
            current_user.totp_enabled_at = datetime.utcnow()
            
            # Generate backup codes
            backup_codes = [secrets.token_hex(4) for _ in range(10)]
            hashed_codes = [generate_password_hash(code) for code in backup_codes]
            current_user.backup_codes = json.dumps(hashed_codes)
            
            db.session.commit()
            
            flash("2FA enabled successfully! Save these backup codes:", "success")
            return render_template("2fa_backup_codes.html", codes=backup_codes)
        else:
            flash("Invalid code. Try again.", "error")
    
    # Generate new secret
    secret = pyotp.random_base32()
    session['temp_totp_secret'] = secret
    
    # Generate QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="OS1 ATS"
    )
    
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    qr_code_data = base64.b64encode(buf.getvalue()).decode()
    
    return render_template("setup_2fa.html", 
                         qr_code=qr_code_data, 
                         secret=secret)

# Modify login to require 2FA
@app.route("/login", methods=["GET", "POST"])
def login():
    # ... existing password check ...
    
    if user and check_password_hash(user.password_hash, password):
        if user.totp_enabled:
            # Store user ID in session and redirect to 2FA page
            session['pending_user_id'] = user.id
            return redirect(url_for('verify_2fa'))
        else:
            login_user(user)
            return redirect(url_for('index'))

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['pending_user_id'])
    
    if request.method == "POST":
        token = request.form.get("token")
        
        # Try TOTP first
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(token):
            session.pop('pending_user_id')
            login_user(user)
            log_audit_event('login', 'auth', '2FA verification successful')
            return redirect(url_for('index'))
        
        # Try backup codes
        if user.backup_codes:
            backup_codes = json.loads(user.backup_codes)
            for i, hashed_code in enumerate(backup_codes):
                if check_password_hash(hashed_code, token):
                    # Remove used backup code
                    backup_codes.pop(i)
                    user.backup_codes = json.dumps(backup_codes)
                    db.session.commit()
                    
                    session.pop('pending_user_id')
                    login_user(user)
                    flash("Backup code used. Please generate new codes.", "warning")
                    log_audit_event('login', 'auth', '2FA backup code used')
                    return redirect(url_for('index'))
        
        log_audit_event('login', 'auth', '2FA verification failed', status='failure')
        flash("Invalid code.", "error")
    
    return render_template("verify_2fa.html")
```

---

### Task 9: Password Reset via Email
**Priority:** 🟡 MEDIUM  
**Time:** 4-5 hours  
**Risk:** MEDIUM

**What:**
- "Forgot Password" link on login page
- Generate secure reset token
- Send reset link via email
- Token expires after 1 hour
- Rate limit reset requests

**Implementation:**
```python
from itsdangerous import URLSafeTimedSerializer

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset')

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset', max_age=expiration)
        return email
    except:
        return None

@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per hour")  # Rate limit
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        
        with Session(engine) as s:
            user = s.scalar(select(User).where(User.email == email))
            
            # Always show success message (security best practice)
            if user:
                token = generate_reset_token(email)
                reset_url = url_for('reset_password', token=token, _external=True)
                
                # Send email
                send_password_reset_email(user.email, reset_url)
                
                log_audit_event('password_reset_request', 'auth', 
                              f'Password reset requested for {email}')
            
            flash("If an account exists, a password reset link has been sent.", "info")
            return redirect(url_for('login'))
    
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = verify_reset_token(token)
    
    if not email:
        flash("Invalid or expired reset link.", "error")
        return redirect(url_for('login'))
    
    if request.method == "POST":
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")
        
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", token=token)
        
        is_valid, message, score = validate_password_strength(password, email)
        if not is_valid:
            flash(message, "error")
            return render_template("reset_password.html", token=token)
        
        with Session(engine) as s:
            user = s.scalar(select(User).where(User.email == email))
            if user:
                user.password_hash = generate_password_hash(password)
                user.password_changed_at = datetime.utcnow()
                user.failed_login_attempts = 0
                user.locked_until = None
                s.commit()
                
                log_audit_event('password_reset_complete', 'auth', 
                              f'Password reset completed for {email}')
                
                flash("Password reset successfully. Please login.", "success")
                return redirect(url_for('login'))
    
    return render_template("reset_password.html", token=token)

def send_password_reset_email(to_email, reset_url):
    """Send password reset email"""
    # Use your existing SMTP setup
    subject = "Password Reset - OS1 ATS"
    body = f"""
    Hello,
    
    You requested a password reset for your OS1 ATS account.
    
    Click the link below to reset your password:
    {reset_url}
    
    This link will expire in 1 hour.
    
    If you didn't request this, please ignore this email.
    
    ---
    OS1 ATS Team
    """
    
    # Use existing send_email function
    send_email(to_email, subject, body)
```

---

## Stage 4: Testing & Documentation (Days 11-14)

### Task 10: Comprehensive Security Testing
**Priority:** 🔴 HIGH  
**Time:** 8-10 hours  
**Risk:** CRITICAL

**What:**
- Unit tests for all security functions
- Integration tests for authentication flows
- Security vulnerability scanning
- Manual penetration testing checklist
- Performance testing with rate limiting

**Test Suite:**
```python
# tests/test_security.py
import pytest
from app import app, User, AuditLog
from werkzeug.security import check_password_hash

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_login_with_valid_credentials(client):
    """Test successful login"""
    response = client.post('/login', data={
        'email': 'admin@os1.com',
        'password': 'Admin123!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Dashboard' in response.data

def test_login_with_invalid_password(client):
    """Test failed login"""
    response = client.post('/login', data={
        'email': 'admin@os1.com',
        'password': 'WrongPassword'
    })
    assert b'Invalid' in response.data

def test_account_lockout(client):
    """Test account locks after 5 failed attempts"""
    for i in range(5):
        client.post('/login', data={
            'email': 'admin@os1.com',
            'password': 'Wrong'
        })
    
    response = client.post('/login', data={
        'email': 'admin@os1.com',
        'password': 'Admin123!'
    })
    assert b'locked' in response.data.lower()

def test_password_complexity(client):
    """Test password strength validation"""
    weak_passwords = [
        'short',
        'nouppercase123!',
        'NOLOWERCASE123!',
        'NoNumbers!',
        'NoSpecialChar123'
    ]
    
    for password in weak_passwords:
        response = client.post('/change-password', data={
            'current_password': 'Admin123!',
            'new_password': password,
            'confirm_password': password
        })
        assert b'must contain' in response.data.lower()

def test_csrf_protection(client):
    """Test CSRF token is required"""
    response = client.post('/apply/test-token', data={
        'name': 'Test',
        'email': 'test@example.com'
    })
    assert response.status_code == 400
    assert b'CSRF' in response.data

def test_rate_limiting(client):
    """Test rate limiting works"""
    for i in range(60):
        response = client.post('/login', data={
            'email': 'test@example.com',
            'password': 'test'
        })
    
    # Should be rate limited
    assert response.status_code == 429

def test_session_timeout(client):
    """Test session expires after timeout"""
    # Login
    client.post('/login', data={
        'email': 'admin@os1.com',
        'password': 'Admin123!'
    })
    
    # Simulate session expiry
    with client.session_transaction() as sess:
        sess['_fresh'] = False
        sess['_permanent'] = False
    
    # Try to access protected page
    response = client.get('/')
    assert response.status_code == 302  # Redirect to login

def test_audit_logging(client):
    """Test audit logs are created"""
    client.post('/login', data={
        'email': 'admin@os1.com',
        'password': 'Admin123!'
    })
    
    with Session(engine) as s:
        logs = s.scalars(select(AuditLog).where(
            AuditLog.event_type == 'login'
        ).order_by(AuditLog.timestamp.desc()).limit(1)).first()
        
        assert logs is not None
        assert logs.user_email == 'admin@os1.com'

def test_file_upload_validation(client):
    """Test file upload restrictions"""
    # Test executable upload
    response = client.post('/apply/test-token', data={
        'cv': (io.BytesIO(b'MZ\x90\x00'), 'malware.exe')
    })
    assert b'not allowed' in response.data.lower()
    
    # Test oversized file
    large_file = io.BytesIO(b'0' * (11 * 1024 * 1024))  # 11MB
    response = client.post('/apply/test-token', data={
        'cv': (large_file, 'large.pdf')
    })
    assert b'too large' in response.data.lower()
```

**Run tests:**
```bash
pytest tests/test_security.py -v --cov=app
```

---

### Task 11: Security Documentation
**Priority:** 🟡 MEDIUM  
**Time:** 4-5 hours  
**Risk:** LOW

**What:**
- Document all security features
- Create security policy document
- Document incident response procedures
- Create CREST compliance checklist
- Document configuration settings

**Documents to create:**
1. `SECURITY_POLICY.md` - Security policies and procedures
2. `INCIDENT_RESPONSE.md` - How to handle security incidents
3. `CREST_COMPLIANCE_CHECKLIST.md` - Full compliance status
4. `SECURITY_CONFIGURATION.md` - All security settings
5. `USER_SECURITY_GUIDE.md` - For end users

---

### Task 12: CREST Penetration Testing Preparation
**Priority:** 🔴 HIGH  
**Time:** 4-6 hours  
**Risk:** LOW

**What:**
- Create test user accounts for pen testers
- Document all endpoints and authentication requirements
- Set up monitoring for pen test activities
- Create backup before testing
- Prepare incident response team

**Deliverables:**
- Pen test scope document
- Test account credentials
- Monitoring dashboard
- Backup verification
- Post-test cleanup procedures

---

## Summary & Timeline

| Stage | Days | Tasks | Priority | Status |
|-------|------|-------|----------|--------|
| Stage 1: Critical Security | 1-3 | 1-4 | 🔴 HIGH | Ready |
| Stage 2: Advanced Security | 4-7 | 5-7 | 🔴 HIGH | Ready |
| Stage 3: Enhanced Features | 8-10 | 8-9 | 🟡 MEDIUM | Ready |
| Stage 4: Testing & Docs | 11-14 | 10-12 | 🔴 CRITICAL | Ready |

**Total Effort:** 60-80 hours over 14 days

---

## Risk Assessment

| Feature | Risk Level | Mitigation |
|---------|------------|------------|
| Re-enable Auth | 🟢 LOW | Admin user exists, tested |
| Account Lockout | 🟡 MEDIUM | Admin unlock feature |
| Password Policy | 🟢 LOW | Clear error messages |
| Session Timeout | 🟢 LOW | Warning before logout |
| Audit Logging | 🟢 LOW | No user-facing changes |
| File Validation | 🟡 MEDIUM | Test with various files |
| 2FA | 🟡 MEDIUM | Backup codes provided |
| Password Reset | 🟡 MEDIUM | Token expiration |
| Testing | 🔴 HIGH | Critical for production |
| Documentation | 🟢 LOW | No code changes |

---

## Immediate Next Steps

**Would you like me to:**

**A) Start with Stage 1 NOW** (Re-enable auth + core security - 3 hours)  
**B) Create a staging environment first** (Test safely before production)  
**C) Show you the implementation code for review** (Before I start)  
**D) Provide a more detailed breakdown** (Of any specific task)

Please let me know how you'd like to proceed!
