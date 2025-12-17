import os, uuid, datetime, json, mimetypes, re, smtplib, ssl, base64, hashlib, hmac, uuid, json, re, time, requests
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, abort
from flask_wtf import FlaskForm
from flask import Response
from wtforms import StringField, TextAreaField, BooleanField, SelectField, IntegerField, FileField, DateTimeLocalField, SubmitField
from typing import Optional, List, Dict, Tuple
from sqlalchemy import or_
import csv
from io import StringIO
from flask import current_app
from flask import Blueprint
from sqlalchemy import exists
from flask import redirect, url_for
from flask import make_response
from pathlib import Path
import os
from werkzeug.utils import secure_filename

from wtforms.validators import DataRequired, Email, Optional as WTOptional
from werkzeug.utils import secure_filename
from sqlalchemy import create_engine, select, ForeignKey, func, Column, text
from sqlalchemy.orm import declarative_base, relationship, Session, selectinload
from sqlalchemy.types import JSON as SA_JSON
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv
load_dotenv()
import requests
from dateutil import parser as dtparser
from sqlalchemy import literal_column
from sqlalchemy import delete
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship, backref
from wtforms import Form
from wtforms.validators import DataRequired
from wtforms import StringField, SelectField
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import session
from openai import OpenAI
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
import datetime
from flask import abort, render_template, request
from sqlalchemy import or_, false
from sqlalchemy.orm import selectinload
from concurrent.futures import ThreadPoolExecutor
executor = ThreadPoolExecutor(max_workers=2)

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

from wtforms import FileField
from wtforms.validators import DataRequired as WTDataRequired

class UploadCVForm(FlaskForm):
    cv = FileField("Upload CV (PDF/DOC/DOCX)", validators=[WTDataRequired()])
    submit = SubmitField("Upload")

# Optional e-sign SDKs
try:
    from dropbox_sign import ApiClient, Configuration
    from dropbox_sign.apis import SignatureRequestApi
    from dropbox_sign.models import SignatureRequestSendRequest, SubSignatureRequestSigner
except Exception:
    ApiClient = None
    Configuration = None
    SignatureRequestApi = None
    SignatureRequestSendRequest = None
    SubSignatureRequestSigner = None

try:
    import docusign_esign as dse
except Exception:
    dse = None

SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///ats.db")
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), "uploads"))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

SECRET_KEY   = os.getenv("FLASK_SECRET_KEY", "dev-secret")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///ats.db")

SUMSUB_APP_TOKEN = os.getenv("SUMSUB_APP_TOKEN")
SUMSUB_SECRET_KEY = os.getenv("SUMSUB_SECRET_KEY")
SUMSUB_BASE_URL = os.getenv("SUMSUB_BASE_URL", "https://api.sumsub.com")
SUMSUB_LEVEL_NAME = os.getenv("SUMSUB_LEVEL_NAME", "basic-kyc-level")

SUMSUB_SDK_URLS = [
    "https://static.sumsub.com/idensic/static/sns-websdk-builder.js",  # legacy path
    "https://static.sumsub.com/idensic/assets/websdk-builder.js",       # newer path
]

# Database initialization with error handling
try:
    engine = create_engine(DATABASE_URL, future=True)
    # Test connection
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    print(f"✓ Database connected: {DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else 'local'}")
except Exception as e:
    print(f"⚠ Database connection warning: {e}")
    print(f"⚠ App will start but features requiring DB will fail")
    # Create engine anyway - Railway needs app to start for healthcheck
    engine = create_engine(DATABASE_URL, future=True)

Base = declarative_base()

APP_ROOT = Path(__file__).parent.resolve()

class RoleType(Base):
    __tablename__ = "role_types"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    default_rate = Column(Integer, default=0)

class EngagementPlan(Base):
    __tablename__ = "engagement_plans"
    id = Column(Integer, primary_key=True, autoincrement=True)
    engagement_id = Column(Integer, ForeignKey("engagements.id"), index=True)
    role_type = Column(String(50), default="")
    planned_count = Column(Integer, default=0)

    # cost to us per head per day
    pay_rate = Column(Integer, default=0)

    # what we bill client per head per day
    charge_rate = Column(Integer, default=0)

    # legacy; keep in sync with charge_rate when saving for backwards reports
    rate = Column(Integer, default=0)

    # version snapshot / plan iteration number
    version_int = Column(Integer, default=1)

TRUSTID_BASE_URL = os.getenv("TRUSTID_BASE_URL", "https://api.trustid.co.uk")
TRUSTID_API_KEY = os.getenv("TRUSTID_API_KEY", "")
TRUSTID_WEBHOOK_SECRET = os.getenv("TRUSTID_WEBHOOK_SECRET", "")

ESIGN_PROVIDER = os.getenv("ESIGN_PROVIDER", "dropbox_sign").lower()

HELLOSIGN_API_KEY = os.getenv("HELLOSIGN_API_KEY", "")

DOCUSIGN_BASE_PATH = os.getenv("DOCUSIGN_BASE_PATH", "https://demo.docusign.net/restapi")
DOCUSIGN_ACCESS_TOKEN = os.getenv("DOCUSIGN_ACCESS_TOKEN", "")
DOCUSIGN_ACCOUNT_ID = os.getenv("DOCUSIGN_ACCOUNT_ID", "")
DOCUSIGN_FROM_NAME = os.getenv("DOCUSIGN_FROM_NAME", "Talent Ops")
DOCUSIGN_FROM_EMAIL = os.getenv("DOCUSIGN_FROM_EMAIL", "talent@example.com")

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "Talent <noreply@example.com>")

_client = None
def get_openai_client():
    """
    Return a clean OpenAI client compatible with the new SDK.

    We:
    - pass api_key directly
    - explicitly build a bare httpx client with trust_env=False so it doesn't
      try to forward local proxy env vars that the SDK then treats as `proxies`
    """

    from openai import OpenAI
    import httpx

    httpx_client = httpx.Client(trust_env=False, timeout=30.0)

    return OpenAI(
        api_key=OPENAI_API_KEY,
        http_client=httpx_client,
    )

APP_BASE_URL = os.getenv("APP_BASE_URL", "http://127.0.0.1:5000")

INTERVIEWER_EMAIL = os.getenv("INTERVIEWER_EMAIL", "interviewer@example.com")
TIMEZONE = os.getenv("TIMEZONE", "Europe/London")

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx"}

# Role taxonomy for planning and reporting
ROLE_TYPES = [
    "Project Director",
    "Project Manager",
    "Ops Manager",
    "Team Leader",
    "Case Handler",
    "Admin",
]

# Opportunity stages (for new Opportunities feature)
OPPORTUNITY_STAGES = [
    "Lead",
    "Closed Won",
    "Closed Lost",
]

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR   = BASE_DIR / "static"
UPLOAD_FOLDER = BASE_DIR / "uploads"
CV_DIR        = UPLOAD_FOLDER / "cvs"

# Ensure folders exist
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
CV_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    static_folder=str(STATIC_DIR),
    template_folder=str(TEMPLATE_DIR),
)

app.config["SECRET_KEY"] = SECRET_KEY
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)

# Initialize Sentry for error monitoring
sentry_dsn = os.getenv('SENTRY_DSN')
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.1,
        environment=os.getenv('FLASK_ENV', 'production'),
    )

# Initialize security middleware
limiter = init_security(app)

# Add security headers to all responses
@app.after_request
def after_request_security(response):
    return add_security_headers(response)

@app.context_processor
def inject_template_helpers():
    def view_exists(name: str) -> bool:
        try:
            return name in current_app.view_functions
        except Exception:
            return False
    return {"view_exists": view_exists}

@app.template_filter('basename')
def basename_filter(s: str) -> str:
    return os.path.basename(s or '')

# Absolute path is safest in dev
app.config.setdefault("UPLOAD_FOLDER", os.path.join(app.root_path, "uploads"))
app.config.setdefault("CV_SUBFOLDER", "cvs")

# --- Auth / sessions ---
login_manager = LoginManager(app)
login_manager.login_view = "login"  # default guard for worker-only pages

def _signer() -> URLSafeTimedSerializer:
    # used for candidate magic links
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="candidate-login")

def get_role_category_names(session: Session) -> List[str]:
    """
    Return role names from taxonomy_categories where type='role',
    ordered by name. Falls back to the hard-coded ROLE_TYPES if empty.
    """
    rows = session.scalars(
        select(TaxonomyCategory)
        .where(TaxonomyCategory.type == "role")
        .order_by(TaxonomyCategory.name.asc())
    ).all()
    names = [r.name for r in rows]
    # Safe fallback for fresh installs (keeps app usable if taxonomy is empty)
    return names or list(ROLE_TYPES)

# -------------- DB Models --------------
from sqlalchemy import String, Integer, DateTime, Boolean

# --- Taxonomy models (subject groups/tags) ---
class CandidateTag(Base):
    __tablename__ = "candidate_tags"
    id = Column(Integer, primary_key=True, autoincrement=True)
    candidate_id = Column(ForeignKey("candidates.id"), index=True, nullable=False)
    tag_id = Column(ForeignKey("taxonomy_tags.id"), index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

# --- DB Models ---
class Engagement(Base):
    __tablename__ = "engagements"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    client = Column(String)
    status = Column(String, default="Active")
    ref = Column(String, unique=True)
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    sow_signed_at = Column(DateTime)
    description = Column(Text, default="")
    opportunity_id = Column(Integer, ForeignKey("opportunities.id"), nullable=True, unique=True)

    # <--- add this
    plan_version = Column(Integer, default=1)

    opportunity = relationship(
        "Opportunity",
        backref=backref("engagement", uselist=False)
    )
    jobs = relationship("Job", back_populates="engagement", cascade="all, delete-orphan")

class Job(Base):
    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    engagement_id = Column(ForeignKey("engagements.id"))
    title = Column(String(200))
    description = Column(String(4000))
    role_type = Column(String(50), default="")
    location = Column(String(200), default="")
    salary_range = Column(String(200), default="")
    status = Column(String(50), default="Open")
    public_token = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    engagement = relationship("Engagement", back_populates="jobs")
    applications = relationship("Application", back_populates="job", cascade="all, delete-orphan")

class RoleAliasForm(FlaskForm):
    canonical = SelectField("Canonical role", choices=[(r, r) for r in ROLE_TYPES], validators=[DataRequired()])
    alias = StringField("Alias (case-insensitive)", validators=[DataRequired()])

class WorkerUser(UserMixin):
    """
    Lightweight adapter around your Users table row to satisfy Flask-Login.
    We'll just carry id + email + name in memory.
    """
    def __init__(self, row):
        self.id = str(row.id)
        self.email = row.email
        self.name = row.name

@login_manager.user_loader
def load_user(user_id: str):
    try:
        uid = int(user_id)
    except Exception:
        return None
    with Session(engine) as s:
        row = s.execute(text("SELECT id, name, email FROM users WHERE id=:i"), {"i": uid}).first()
        if not row:
            return None
        # row is a Row tuple (id, name, email)
        class _Obj: pass
        obj = _Obj()
        obj.id, obj.name, obj.email = row[0], row[1], row[2]
        return WorkerUser(obj)

def sign_request(method, path, body=None):
    ts = str(int(time.time()))
    payload = (ts + method.upper() + path + (body or "")).encode()
    signature = hmac.new(SUMSUB_SECRET_KEY.encode(), payload, hashlib.sha256).hexdigest()
    return {"X-App-Token": SUMSUB_APP_TOKEN, "X-App-Access-Ts": ts, "X-App-Access-Sig": signature}

def _cv_upload_root():
    # wherever you store CVs on disk
    return os.path.join(app.root_path, "uploads", "cvs")

# --- Role/session helpers ---

def worker_required(fn):
    """Guard routes for internal workers (Flask-Login)."""
    from functools import wraps
    @wraps(fn)
    def _wrap(*a, **kw):
        if not current_user.is_authenticated:
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return _wrap

def candidate_required(fn):
    """Guard routes for candidate self-service (magic-link)."""
    from functools import wraps
    @wraps(fn)
    def _wrap(*a, **kw):
        if not session.get("candidate_id"):
            return redirect(url_for("candidate_login", next=request.path))
        return fn(*a, **kw)
    return _wrap

class WorkerLoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")

class WorkerSignupForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Create account")

class CandidateLoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send me a login link")

class Timesheet(Base):
    __tablename__ = "timesheets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False)
    engagement_id = Column(Integer, nullable=False)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    hours = Column(Integer, default=0)
    notes = Column(String(4000), default="")
    status = Column(String(50), default="Draft")
    submitted_at = Column(DateTime, nullable=True)

class Candidate(Base):
    __tablename__ = "candidates"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200))
    email = Column(String(200))
    phone = Column(String(50), default="")
    skills = Column(String(2000), default="")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # card fields…
    onboarded_at = Column(DateTime, nullable=True)
    esign_status = Column(String(50), default=None)
    trustid_rtw_date = Column(DateTime, nullable=True)
    trustid_idv_date = Column(DateTime, nullable=True)
    trustid_dbs_date = Column(DateTime, nullable=True)
    updated_cv_requested_at = Column(DateTime, nullable=True)

    # NEW
    ai_summary = Column(String(6000), default="")

    documents = relationship("Document", back_populates="candidate", cascade="all, delete-orphan")

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True, autoincrement=True)
    candidate_id = Column(ForeignKey("candidates.id"))
    doc_type = Column(String(50), default="cv")
    filename = Column(String(500))
    original_name = Column(String(500))
    uploaded_at = Column(DateTime, default=datetime.datetime.utcnow)
    candidate = relationship("Candidate", back_populates="documents")

class Application(Base):
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(ForeignKey("jobs.id"))
    candidate_id = Column(ForeignKey("candidates.id"))
    cover_note = Column(String(4000), default="")
    status = Column(String(50), default="New")  # Pipeline status
    ai_score = Column(Integer, default=0)
    ai_summary = Column(String(6000), default="")
    ai_explanation = Column(String(8000), default="")  # <-- NEW: store "why this score"
    interview_scheduled_at = Column(DateTime, nullable=True)
    interview_completed_at = Column(DateTime, nullable=True)

    # ✅ make sure THIS is present:
    interview_notes = Column(Text, default="")

    onboarding_email_sent = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    job = relationship("Job", back_populates="applications")
    candidate = relationship("Candidate")

class TrustIDCheck(Base):
    __tablename__ = "trustid_checks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    application_id = Column(ForeignKey("applications.id"))
    rtw = Column(Boolean, default=False)
    idv = Column(Boolean, default=True)
    dbs = Column(Boolean, default=False)
    trustid_application_id = Column(String(100), default="")
    status = Column(String(50), default="Created")
    result_json = Column(String(20000), default="")

class Shortlist(Base):
    __tablename__ = "shortlists"
    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(ForeignKey("jobs.id"), index=True, nullable=False)
    candidate_id = Column(ForeignKey("candidates.id"), index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class ESigRequest(Base):
    __tablename__ = "esign_requests"
    id = Column(Integer, primary_key=True, autoincrement=True)
    application_id = Column(ForeignKey("applications.id"))
    provider = Column(String(50), default="dropbox_sign")
    request_id = Column(String(100), default=""
    )
    status = Column(String(50), default="Draft")  # Draft, Sent, Signed, Declined, Error
    sent_at = Column(DateTime, nullable=True)
    signed_at = Column(DateTime, nullable=True)

class WebhookEvent(Base):
    __tablename__ = "webhook_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    source = Column(String(50))
    event_type = Column(String(100))
    payload = Column(String(40000))
    received_at = Column(DateTime, default=datetime.datetime.utcnow)

# --- Taxonomy (DB-driven) ---
class TaxonomyCategory(Base):
    __tablename__ = "taxonomy_categories"
    id = Column(Integer, primary_key=True, autoincrement=True)
    # 'role' or 'subject'
    type = Column(String(20), nullable=False)
    name = Column(String(200), nullable=False, unique=False)

    tags = relationship("TaxonomyTag", back_populates="category", cascade="all, delete-orphan")

class TaxonomyTag(Base):
    __tablename__ = "taxonomy_tags"
    id = Column(Integer, primary_key=True, autoincrement=True)
    category_id = Column(ForeignKey("taxonomy_categories.id"), index=True, nullable=False)
    tag = Column(String(200), nullable=False)

    category = relationship("TaxonomyCategory", back_populates="tags")

# ---- Opportunities model ----
class Opportunity(Base):
    __tablename__ = "opportunities"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    client = Column(String)
    stage = Column(String)
    owner = Column(String)
    est_start = Column(DateTime)
    est_value = Column(Integer)
    probability = Column(Integer, default=0)
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    _engagement_id = Column(Integer)
    _engagement_ref = Column(String)

    # NEW client contact fields
    client_contact_name  = Column(String, default="")
    client_contact_role  = Column(String, default="")
    client_contact_phone = Column(String, default="")
    client_contact_email = Column(String, default="")

from public import public_bp
app.register_blueprint(public_bp)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")  # for session

def _basename_safe(name: str) -> str:
    # keep it simple & safe for URLs/filesystems
    import re
    base = os.path.basename(name or "")
    return re.sub(r"[^A-Za-z0-9._-]", "_", base)

def _cv_fs_path(doc) -> str:
    """
    Resolve absolute path for a CV Document row that stores a basename in filename.
    """
    return os.path.join(CV_DIR, _basename_safe(getattr(doc, "filename", "") or ""))

def _async_enrich(app_id: int):
    """
    Background enrichment after an application is created:
    - Extract CV text
    - Build AI summary
    - Compute AI match score + explanation
    """
    from sqlalchemy.orm import Session as SASession
    from sqlalchemy import select

    try:
        with SASession(engine) as s:
            appn = s.get(Application, app_id)
            if not appn:
                return

            cand = s.get(Candidate, appn.candidate_id)
            job  = s.get(Job, appn.job_id)
            if not cand or not job:
                return

            # Latest CV for candidate
            order_col = getattr(Document, "uploaded_at", Document.id)
            doc = s.execute(
                select(Document)
                .where(Document.candidate_id == cand.id)
                .where(getattr(Document, "doc_type", Document.doc_type) == "cv")
                .order_by(order_col.desc())
                .limit(1)
            ).scalar_one_or_none()
            if not doc:
                return

            # Extract text
            try:
                cv_text = extract_cv_text(doc) or ""
            except TypeError:
                # handle legacy extractor signature
                try:
                    from app import _doc_file_path
                    cv_text = extract_cv_text(_doc_file_path(doc)) or ""
                except Exception:
                    cv_text = ""
            except Exception:
                cv_text = ""

            # AI summary
            try:
                if cv_text.strip():
                    appn.ai_summary = (ai_summarise(cv_text) or "")[:7999]
            except Exception:
                pass

            # AI score + explanation
            try:
                if cv_text.strip():
                    payload = ai_score_with_explanation(job.description or "", cv_text) or {}
                    score   = _pick_ai_score(payload)
                    appn.ai_score = score
                    appn.ai_explanation = (payload.get("explanation") or "")[:7999]
            except Exception:
                pass

            s.commit()
    except Exception:
        # never crash the app if background worker fails
        current_app.logger.exception("async enrich failed")

def _doc_file_path(doc_or_path) -> str:
    """
    Return the absolute on-disk path to a CV document.
    Accepts a Document model or a string filename.
    Always strips any accidental 'uploads/cvs/' prefix using basename().
    """
    base = _cv_upload_root()
    if isinstance(doc_or_path, str):
        fname = os.path.basename(doc_or_path)
    else:
        fname = os.path.basename(getattr(doc_or_path, "filename", "") or "")
    return os.path.join(base, fname)

def _doc_file_path(doc) -> str:
    """
    Resolve where a CV file lives.
    - If doc.<any path field> exists on disk, return it.
    - Else try UPLOAD_FOLDER[/cvs]/<basename(original_name or filename)>.
    - Else try UPLOAD_FOLDER[/cvs]/<doc.id> with common extensions.
    """
    import os

    # 0) Direct path fields take priority
    for attr in ("path", "file_path", "storage_path", "stored_path", "full_path"):
        p = getattr(doc, attr, None)
        if p and os.path.exists(p):
            return p

    # 1) Build from configured upload root
    root = current_app.config.get("UPLOAD_FOLDER") or os.path.join(current_app.root_path, "uploads")
    cv_sub = current_app.config.get("CV_SUBFOLDER", "cvs")

    # Ensure absolute root
    root = os.path.abspath(root)

    # 2) Only ever use the basename of the stored name (avoid duplicating folders)
    raw_name = (getattr(doc, "original_name", None) or getattr(doc, "filename", None) or "")
    base_name = os.path.basename(raw_name)  # <-- key line: strips 'uploads/cvs/' if present

    candidates = []

    if base_name:
        candidates += [
            os.path.join(root, cv_sub, base_name),
            os.path.join(root, base_name),
        ]

    # 3) Fallbacks using the document id
    doc_id = getattr(doc, "id", None)
    if doc_id is not None:
        candidates += [
            os.path.join(root, cv_sub, f"{doc_id}.docx"),
            os.path.join(root, cv_sub, f"{doc_id}.pdf"),
            os.path.join(root, f"{doc_id}.docx"),
            os.path.join(root, f"{doc_id}.pdf"),
        ]

    # 4) Return the first that exists
    for p in candidates:
        p2 = os.path.normpath(p)
        if os.path.exists(p2):
            return p2

    # 5) Last resort: return the first candidate (normalized), even if not existing,
    # so callers can log what was attempted.
    return os.path.normpath(candidates[0]) if candidates else os.path.join(root, cv_sub)

def extract_cv_text(doc_or_path: object) -> str:
    """
    Robust text extractor that accepts:
      - a Document ORM row (with filename/original_name), or
      - a string file path
    Supports .pdf, .docx, and plain text fallback.
    """
    # Resolve inputs → path & original name (for extension checks)
    file_path: Optional[str] = None
    original_name: str = ""

    if isinstance(doc_or_path, str):
        file_path = doc_or_path
        original_name = doc_or_path
    else:
        try:
            # ORM row
            file_path = _doc_file_path(doc_or_path)
            original_name = (getattr(doc_or_path, "original_name", None)
                             or getattr(doc_or_path, "filename", None)
                             or "")
        except Exception:
            return ""

    if not file_path or not os.path.exists(file_path):
        return ""

    name_lc = (original_name or file_path).lower()

    # --- PDF ---
    if name_lc.endswith(".pdf"):
        try:
            import pdfplumber
            with pdfplumber.open(file_path) as pdf:
                pages = [(p.extract_text() or "") for p in pdf.pages]
            txt = "\n".join(pages).strip()
            if txt:
                return txt
        except Exception as e:
            current_app.logger.warning(f"pdf extract failed for {file_path}: {e}")

    # --- DOCX ---
    if name_lc.endswith(".docx"):
        try:
            import docx
            d = docx.Document(file_path)
            txt = "\n".join([p.text for p in d.paragraphs]).strip()
            if txt:
                return txt
        except Exception as e:
            current_app.logger.warning(f"docx extract failed for {file_path}: {e}")

    # --- Plain text fallback ---
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read().strip()
    except Exception:
        return ""

def _pick_ai_score(payload) -> Optional[int]:
    """
    Normalise different scorer payloads into a single int 0–100 (or None).
    Looks for: blended_score, final, score, match, overall, etc.
    """
    if not isinstance(payload, dict):
        return None
    keys = [
        "blended_score", "final", "score", "match", "overall", "overall_score",
        "final_score", "blended", "result"
    ]
    for k in keys:
        if k in payload:
            try:
                v = payload[k]
                if isinstance(v, (int, float)) and 0 <= int(v) <= 100:
                    return int(v)
                # sometimes models return 0–1
                if isinstance(v, (int, float)) and 0 <= float(v) <= 1.0:
                    return int(round(float(v) * 100))
            except Exception:
                pass
    return None

def save_cv(file_storage) -> str:
    """
    Save a CV to <static>/uploads/cvs and return the *basename only*.
    """
    from werkzeug.utils import secure_filename
    raw = secure_filename(file_storage.filename or "")
    ext = (os.path.splitext(raw)[1] or "").lower()
    if ext not in {".pdf", ".docx", ".doc", ".txt", ""}:
        # allow unknown but keep an extension if user has one
        pass
    fname = _basename_safe(f"{uuid.uuid4().hex}{ext}")
    dest  = os.path.join(CV_DIR, fname)
    file_storage.save(dest)
    return fname  # <-- store *only* this in Document.filename

# ---- Lightweight schema patches for existing SQLite DBs ----
def ensure_schema():
    with engine.begin() as conn:
        # ===== jobs table =====
        try:
            conn.execute(text("ALTER TABLE jobs ADD COLUMN role_type TEXT DEFAULT ''"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE jobs ADD COLUMN status TEXT DEFAULT 'Open'"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE jobs ADD COLUMN location TEXT DEFAULT ''"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE jobs ADD COLUMN salary_range TEXT DEFAULT ''"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE jobs ADD COLUMN public_token TEXT UNIQUE"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE jobs ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP"))
        except Exception:
            pass
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)"))
        except Exception:
            pass
        try:
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_public_token ON jobs(public_token)"))
        except Exception:
            pass

        # ===== applications table =====
        for coldef in [
            "interview_completed_at DATETIME",
            "interview_notes TEXT DEFAULT ''",
            "ai_explanation TEXT DEFAULT ''",
            "ai_score INTEGER DEFAULT 0",
            "ai_summary TEXT DEFAULT ''",
            "onboarding_email_sent BOOLEAN DEFAULT 0",
            "interview_scheduled_at DATETIME",
            "status TEXT DEFAULT 'New'",
            "created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
        ]:
            try:
                conn.execute(text(f"ALTER TABLE applications ADD COLUMN {coldef}"))
            except Exception:
                pass

        # ===== candidates table =====
        try:
            conn.execute(text("ALTER TABLE candidates ADD COLUMN ai_summary TEXT DEFAULT ''"))
        except Exception:
            pass
        for coldef in [
            "onboarded_at DATETIME",
            "esign_status TEXT",
            "trustid_rtw_date DATETIME",
            "trustid_idv_date DATETIME",
            "trustid_dbs_date DATETIME",
            "updated_cv_requested_at DATETIME",
        ]:
            try:
                conn.execute(text(f"ALTER TABLE candidates ADD COLUMN {coldef}"))
            except Exception:
                pass
        try:
            conn.execute(text("ALTER TABLE candidates ADD COLUMN phone TEXT DEFAULT ''"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE candidates ADD COLUMN skills TEXT DEFAULT ''"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE candidates ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP"))
        except Exception:
            pass
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_candidates_created_at ON candidates(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_candidates_email ON candidates(email)",
            "CREATE INDEX IF NOT EXISTS idx_candidates_name ON candidates(name)",
        ]:
            try:
                conn.execute(text(stmt))
            except Exception:
                pass

        # ===== documents table =====
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_documents_candidate ON documents(candidate_id)",
            "CREATE INDEX IF NOT EXISTS idx_documents_uploaded_at ON documents(uploaded_at)",
        ]:
            try:
                conn.execute(text(stmt))
            except Exception:
                pass

        # ===== shortlists table =====
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS shortlists (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              job_id INTEGER NOT NULL,
              candidate_id INTEGER NOT NULL,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """))
        except Exception:
            pass
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_shortlists_job ON shortlists(job_id)",
            "CREATE INDEX IF NOT EXISTS idx_shortlists_candidate ON shortlists(candidate_id)",
        ]:
            try:
                conn.execute(text(stmt))
            except Exception:
                pass

        # ===== taxonomy tables =====
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS taxonomy_categories (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              type TEXT NOT NULL,
              name TEXT NOT NULL
            )
            """))
        except Exception:
            pass
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS taxonomy_tags (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              category_id INTEGER NOT NULL REFERENCES taxonomy_categories(id) ON DELETE CASCADE,
              tag TEXT NOT NULL
            )
            """))
        except Exception:
            pass
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS candidate_tags (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              candidate_id INTEGER NOT NULL,
              tag_id INTEGER NOT NULL,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """))
        except Exception:
            pass
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_tax_cat_type ON taxonomy_categories(type)",
            "CREATE INDEX IF NOT EXISTS idx_tax_tags_cat ON taxonomy_tags(category_id)",
            "CREATE INDEX IF NOT EXISTS idx_candidate_tags_cand ON candidate_tags(candidate_id)",
        ]:
            try:
                conn.execute(text(stmt))
            except Exception:
                pass

        # ===== role_aliases table =====
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS role_aliases (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              canonical TEXT NOT NULL,
              alias TEXT NOT NULL
            )
            """))
        except Exception:
            pass
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_role_alias_canon ON role_aliases(canonical)"))
        except Exception:
            pass
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_role_alias_alias ON role_aliases(alias)"))
        except Exception:
            pass

        # ===== users table =====
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT,
              email TEXT UNIQUE,
              pw_hash TEXT,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """))
        except Exception:
            pass
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)"))
        except Exception:
            pass

        # ===== timesheets table =====
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS timesheets (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              engagement_id INTEGER NOT NULL,
              period_start DATETIME NOT NULL,
              period_end DATETIME NOT NULL,
              hours INTEGER DEFAULT 0,
              notes TEXT,
              status TEXT DEFAULT 'Draft',
              submitted_at DATETIME
            )
            """))
        except Exception:
            pass
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_timesheets_eng_period ON timesheets(engagement_id, period_start)",
            "CREATE INDEX IF NOT EXISTS idx_timesheets_user_period ON timesheets(user_id, period_start)",
        ]:
            try:
                conn.execute(text(stmt))
            except Exception:
                pass

        # ===== engagements table =====
        try:
            conn.execute(text("ALTER TABLE engagements ADD COLUMN ref TEXT"))
        except Exception:
            pass
        try:
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_engagements_ref ON engagements(ref)"))
        except Exception:
            pass

        for coldef in [
            "sow_signed_at DATETIME",
            "description TEXT DEFAULT ''",
            "start_date DATETIME",
            "end_date DATETIME",
            "opportunity_id INTEGER UNIQUE",
            "plan_version INTEGER DEFAULT 1"
        ]:
            try:
                conn.execute(text(f"ALTER TABLE engagements ADD COLUMN {coldef}"))
            except Exception:
                pass

        try:
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_engagements_opp ON engagements(opportunity_id)"))
        except Exception:
            pass

        # ===== opportunities table =====
        for coldef in [
            "_engagement_id INTEGER",
            "_engagement_ref TEXT",
            "created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
            "probability INTEGER DEFAULT 0",
            "notes TEXT DEFAULT ''",
            "client_contact_name TEXT",
            "client_contact_role TEXT",
            "client_contact_phone TEXT",
            "client_contact_email TEXT"
        ]:
            try:
                conn.execute(text(f"ALTER TABLE opportunities ADD COLUMN {coldef}"))
            except Exception:
                pass
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_opps_engid ON opportunities(_engagement_id)"))
        except Exception:
            pass

        # ===== engagement_plans table =====
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS engagement_plans (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              engagement_id INTEGER,
              role_type TEXT DEFAULT '',
              planned_count INTEGER DEFAULT 0,
              pay_rate INTEGER DEFAULT 0,
              charge_rate INTEGER DEFAULT 0,
              -- legacy 'rate' kept for backwards compat; mirrors charge_rate
              rate INTEGER DEFAULT 0,
              version_int INTEGER DEFAULT 1
            )
            """))
        except Exception:
            pass

        # backfill new columns if table pre-existed
        for coldef in [
            "pay_rate INTEGER DEFAULT 0",
            "charge_rate INTEGER DEFAULT 0",
            "version_int INTEGER DEFAULT 1",
            "rate INTEGER DEFAULT 0"
        ]:
            try:
                conn.execute(text(f"ALTER TABLE engagement_plans ADD COLUMN {coldef}"))
            except Exception:
                pass

        # ===== trustid_checks table =====
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS trustid_checks (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              application_id INTEGER,
              rtw BOOLEAN DEFAULT 0,
              idv BOOLEAN DEFAULT 1,
              dbs BOOLEAN DEFAULT 0,
              trustid_application_id TEXT DEFAULT '',
              status TEXT DEFAULT 'Created',
              result_json TEXT DEFAULT ''
            )
            """))
        except Exception:
            pass

        # ===== esign_requests table =====
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS esign_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              application_id INTEGER,
              provider TEXT DEFAULT 'dropbox_sign',
              request_id TEXT DEFAULT '',
              status TEXT DEFAULT 'Draft',
              sent_at DATETIME,
              signed_at DATETIME
            )
            """))
        except Exception:
            pass

        # ===== webhook_events table =====
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS webhook_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              source TEXT,
              event_type TEXT,
              payload TEXT,
              received_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """))
        except Exception:
            pass

        # ===== role_types table =====
        try:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS role_types (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT UNIQUE NOT NULL,
              default_rate INTEGER DEFAULT 0
            )
            """))
        except Exception:
            pass

        # ===== Helpful engagement ref backfill =====
        try:
            existing_refs = [r[0] for r in conn.execute(
                text("SELECT ref FROM engagements WHERE ref IS NOT NULL AND ref <> ''")
            ).all()]
            import re as _re
            prefix = "EG"
            width = 3
            max_n = 0
            for ref in existing_refs:
                m = _re.fullmatch(rf"{_re.escape(prefix)}(\d+)", ref or "")
                if m:
                    try:
                        max_n = max(max_n, int(m.group(1)))
                    except Exception:
                        pass
            rows_to_fill = conn.execute(
                text("SELECT id FROM engagements WHERE ref IS NULL OR ref = '' ORDER BY id ASC")
            ).all()
            for (eid,) in rows_to_fill:
                max_n += 1
                new_ref = f"{prefix}{str(max_n).zfill(width)}"
                conn.execute(text("UPDATE engagements SET ref=:r WHERE id=:i"), {"r": new_ref, "i": eid})
        except Exception:
            pass

        # ===== Seed taxonomy & role_aliases if empty =====
        try:
            existing = conn.execute(text("SELECT COUNT(1) FROM taxonomy_categories")).scalar() or 0
            if existing == 0:
                role_names = [
                    'Project Director','Project Manager','Ops Manager',
                    'Team Leader','Case Handler','Admin'
                ]
                for rn in role_names:
                    conn.execute(
                        text("INSERT INTO taxonomy_categories(type,name) VALUES('role', :n)"),
                        {"n": rn},
                    )

                subjects = {
                    "Financial Crime / Compliance": [
                        "AML","KYC","CDD","EDD","Sanctions","Screening",
                        "TM (Transaction Monitoring)","FRA","SAR/STR","PEP","Adverse Media"
                    ],
                    "Case Handling / QA / Ops": [
                        "Case Handling","Quality Assurance","MI/Reporting",
                        "Playbooks","Workflows","SLA Management"
                    ],
                    "Domains": [
                        "Retail Banking","Corporate Banking","FinTech",
                        "Payments","Crypto","Wealth/Private Banking"
                    ],
                    "Tools & Platforms": [
                        "Actimize","Pega","Mantas","Nice","Salesforce",
                        "Dynamics","Oracle","Workday","Excel","SQL"
                    ],
                }
                for cat, tags in subjects.items():
                    conn.execute(
                        text("INSERT INTO taxonomy_categories(type,name) VALUES('subject', :n)"),
                        {"n": cat},
                    )
                    cat_id = conn.execute(
                        text("SELECT id FROM taxonomy_categories WHERE type='subject' AND name=:n ORDER BY id DESC LIMIT 1"),
                        {"n": cat},
                    ).scalar()
                    for t in tags:
                        conn.execute(
                            text("INSERT INTO taxonomy_tags(category_id, tag) VALUES(:cid, :tag)"),
                            {"cid": cat_id, "tag": t},
                        )
        except Exception:
            pass

        try:
            n_alias = conn.execute(text("SELECT COUNT(1) FROM role_aliases")).scalar() or 0
            if n_alias == 0:
                seeds = [
                    ("Project Director", "programme director"),
                    ("Project Director", "program director"),
                    ("Project Director", "pd"),
                    ("Project Manager",  "programme manager"),
                    ("Project Manager",  "program manager"),
                    ("Project Manager",  "pm"),
                    ("Project Manager",  "project lead"),
                    ("Ops Manager",      "operations manager"),
                    ("Ops Manager",      "service delivery manager"),
                    ("Team Leader",      "team lead"),
                    ("Team Leader",      "supervisor"),
                    ("Case Handler",     "kyc analyst"),
                    ("Case Handler",     "aml analyst"),
                    ("Case Handler",     "investigator"),
                    ("Admin",            "administrator"),
                    ("Admin",            "office admin"),
                ]
                for canon, alias in seeds:
                    conn.execute(
                        text("INSERT INTO role_aliases(canonical, alias) VALUES(:c, :a)"),
                        {"c": canon, "a": alias},
                    )
        except Exception:
            pass

        # ===== Seed role_types table =====
        try:
            count_roles = conn.execute(text("SELECT COUNT(1) FROM role_types")).scalar() or 0
            if count_roles == 0:
                for r in ROLE_TYPES:
                    conn.execute(
                        text("INSERT INTO role_types (name, default_rate) VALUES (:n, 0)"),
                        {"n": r},
                    )
        except Exception:
            pass

# Run on import
ensure_schema()
Base.metadata.create_all(engine)

# ---------- Taxonomy tagging helpers ----------
WORD = r"[A-Za-z][A-Za-z\-/&\.\(\) ]+[A-Za-z]"

def _collect_text_for_candidate(session: Session, cand: Candidate) -> str:
    """Return searchable text: latest CV + name + existing skills."""
    doc = session.scalar(
        select(Document)
        .where(Document.candidate_id == cand.id)
        .order_by(Document.uploaded_at.desc())
    )
    parts = [cand.name or "", cand.email or "", cand.skills or ""]
    if doc:
        parts.append(extract_cv_text(doc) or "")
    text = " \n ".join(p for p in parts if p).lower()
    # compress whitespace
    text = re.sub(r"\s+", " ", text)
    return text

def _job_is_open(job) -> bool:
    if job is None:
        return False
    status = (getattr(job, "status", "") or "").strip().lower()
    if status in {"withdrawn","closed","filled","archived","cancelled","canceled"}:
        return False
    # also treat explicit timestamps if you ever add them
    if getattr(job, "closed_at", None) is not None: return False
    if getattr(job, "archived_at", None) is not None: return False
    return True

def _load_role_aliases(session: Session) -> dict:
    """
    Merge built-in aliases with DB-managed aliases.
    Returns: {canonical_lower: set(alias_lower, ...)}
    """
    # start from your existing dict (if you want to keep the built-ins)
    base = {
        "project director": {"programme director","program director","pd","delivery director"},
        "project manager":  {"project lead","pm","programme manager","program manager","scrum master"},
        "ops manager":      {"operations manager","operations lead","ops lead","service delivery manager"},
        "team leader":      {"supervisor","team lead","shift lead","coach"},
        "case handler":     {"investigator","analyst","kyc analyst","aml analyst","qa analyst","caseworker"},
        "admin":            {"coordinator","assistant","administrator","pa","ea","office admin"},
    }
    rows = session.execute(text("SELECT canonical, alias FROM role_aliases")).all()
    for canon, alias in rows:
        if not canon or not alias:
            continue
        base.setdefault(canon.strip().lower(), set()).add(alias.strip().lower())
    return base

def _retag_candidate_skills(s, cand, overwrite: bool = False):
    """
    Derive tags/role from candidate text and update:
      - Candidate.skills (human-readable)
      - CandidateTag (normalized join rows)
    Uses the taxonomy helpers already in this codebase.
    """
    # Collect text (CV text preferred; falls back to freeform)
    text_lc = _collect_text_for_candidate(s, cand)
    if not text_lc:
        return

    # Load taxonomy terms once
    groups = _get_subject_term_set(s)
    term_list = [t for t in groups.get("__all__", [])]

    # Derive role + subject tags
    role = _normalise_role(text_lc)
    tags = _derive_subject_tags(text_lc, term_list)

    # ---------- Update Candidate.skills (readable) ----------
    current = (cand.skills or "").strip()
    existing_tokens = {w.strip().lower() for w in re.split(r"[,/|;]", current) if w.strip()}

    # Ensure role token is first (if found)
    parts = []
    if role:
        parts.append(role)

    # Add new tags (avoid duplicates, case-insensitive)
    new_tags = []
    for t in sorted(tags, key=str.lower):
        if t.lower() not in existing_tokens:
            new_tags.append(t)

    if overwrite:
        merged = ", ".join(parts + new_tags)
        if current:
            # keep any freeform skills too
            merged = (merged + (" | " if merged and current else "") + current).strip()
        cand.skills = merged or current
    else:
        # append tags that aren't already there
        if parts:
            for rt in parts:
                if rt.lower() not in existing_tokens:
                    current = (f"{rt} | " + current).strip(" |")
                    existing_tokens.add(rt.lower())
        if new_tags:
            add_str = ", ".join(new_tags)
            cand.skills = (current + (" | " if current else "") + add_str).strip()
        else:
            cand.skills = current

    # ---------- Sync CandidateTag (normalized) ----------
    # Map existing tag ids for quick checks
    existing_rels = s.scalars(
        select(CandidateTag).where(CandidateTag.candidate_id == cand.id)
    ).all()
    existing_tag_ids = {r.tag_id for r in existing_rels}

    # Lookup tag ids by name (case-insensitive)
    if tags:
        tag_rows = s.scalars(
            select(TaxonomyTag).where(func.lower(TaxonomyTag.tag).in_([t.lower() for t in tags]))
        ).all()
        for tg in tag_rows:
            if tg.id not in existing_tag_ids:
                s.add(CandidateTag(candidate_id=cand.id, tag_id=tg.id))

# --- Tag matching helper (place near other helpers) ---
def _match_tags_from_text(s, text: str) -> List[TaxonomyTag]:
    """Return TaxonomyTag rows whose tag string appears (case-insensitive) in text."""
    text_lc = (text or "").lower()
    if not text_lc.strip():
        return []
    all_tags = s.scalars(select(TaxonomyTag)).all()
    hits: List[TaxonomyTag] = []
    for tg in all_tags:
        token = (tg.tag or "").strip()
        if token and token.lower() in text_lc:
            hits.append(tg)
    return hits

def _create_engagement_from_opportunity(s: Session, opp: Opportunity) -> Engagement:
    existing = s.scalar(select(Engagement).where(Engagement.opportunity_id == opp.id))
    if existing:
        return existing

    new_ref = _next_engagement_ref(s)

    e = Engagement(
        ref=new_ref,
        name=opp.name,
        client=opp.client or "",
        status="Active",
        start_date=opp.est_start,              # now valid
        description=(opp.notes or ""),
        opportunity_id=opp.id,
    )
    s.add(e)
    s.flush()
    return e

def create_engagement_for_opportunity(s, opp: Opportunity) -> Engagement:
    # create the engagement with sensible defaults
    e = Engagement(
        name=opp.name or f"Engagement for {opp.client or 'Unknown Client'}",
        client=opp.client or "",
        status="Active",
        description=opp.notes or "",
        opportunity=opp,               # sets e.opportunity_id automatically
    )
    s.add(e)
    s.flush()  # get e.id

    # ensure engagement has a ref (EG00X...) if your ref backfill didn’t set it yet
    if not e.ref:
        # find next numeric
        prefix, width = "EG", 3
        max_n = s.execute(text("""
            SELECT COALESCE(MAX(CAST(SUBSTR(ref, 3) AS INTEGER)), 0)
            FROM engagements
            WHERE ref LIKE :patt
        """), {"patt": f"{prefix}%"}).scalar() or 0
        e.ref = f"{prefix}{str(max_n + 1).zfill(width)}"

    # cache back onto opportunity for quick linking in UI
    opp._engagement_id = e.id
    opp._engagement_ref = e.ref

    return e

def _get_subject_term_set(session: Session) -> Dict[str, List[str]]:
    """
    Build {category_name: [tag, ...]} from DB taxonomy.
    Also returns a flat set of all tags under key '__all__'.
    """
    cats = session.execute(
        text("SELECT c.id, c.name FROM taxonomy_categories c WHERE c.type='subject'")
    ).all()
    result: Dict[str, List[str]] = {}
    all_terms: List[str] = []
    for cid, cname in cats:
        tags = [t for (t,) in session.execute(
            text("SELECT tag FROM taxonomy_tags WHERE category_id=:cid"),
            {"cid": cid}
        ).all()]
        result[cname] = tags
        all_terms.extend(tags)
    result["__all__"] = sorted(set(all_terms), key=lambda s: s.lower())
    return result

def parse_date_dmy(s: Optional[str]):
    if not s:
        return None
    try:
        # dayfirst=True so "09-10-2025" is 9th Oct (not Sept 10)
        return dtparser.parse(s, dayfirst=True).replace(tzinfo=None)
    except Exception:
        return None

def format_date_dmy(dt: Optional[datetime.datetime]) -> str:
    if not dt:
        return ""
    return dt.strftime("%d-%m-%Y")

# --- Sequential engagement ref (EG001, EG002, ...) ---
def _next_engagement_ref(session: Session, prefix: str = "EG", width: int = 3) -> str:
    import re as _re
    # pull all refs that match pattern and take max
    rows = session.execute(text(
        "SELECT ref FROM engagements WHERE ref IS NOT NULL AND ref <> ''"
    )).all()
    max_n = 0
    for (ref,) in rows:
        m = _re.fullmatch(rf"{_re.escape(prefix)}(\d+)", ref or "")
        if m:
            try:
                max_n = max(max_n, int(m.group(1)))
            except ValueError:
                pass
    return f"{prefix}{str(max_n + 1).zfill(width)}"

# --- WTForm for Create Engagement (vertical layout fields) ---
class CreateEngagementForm(FlaskForm):
    name = StringField("Engagement Name", validators=[DataRequired()])
    client = StringField("Client", validators=[WTOptional()])
    status = SelectField("Status",
                         choices=[("Active","Active"), ("On Hold","On Hold"), ("Finished","Finished")],
                         default="Active")
    start_date = StringField("Start Date (DD-MM-YYYY)", validators=[WTOptional()])
    end_date = StringField("End Date (DD-MM-YYYY)", validators=[WTOptional()])
    sow_signed_on = StringField("Statement of Work Signed (DD-MM-YYYY)", validators=[WTOptional()])
    description = TextAreaField("Description of Work", validators=[WTOptional()])

def _derive_subject_tags(text_lc: str, all_terms: List[str]) -> List[str]:
    """Match whole-word-ish terms (case-insensitive) within candidate text."""
    found = []
    for term in all_terms:
        t = term.strip()
        if not t:
            continue
        # allow terms with / or () etc; use simple contains with word guards when safe
        # If simple letters/spaces, enforce word boundaries; otherwise fallback to 'in'
        if re.fullmatch(r"[A-Za-z0-9 ]+", t):
            pat = r"(?:^|[^A-Za-z0-9])" + re.escape(t.lower()) + r"(?:[^A-Za-z0-9]|$)"
            if re.search(pat, text_lc):
                found.append(term)
        else:
            if t.lower() in text_lc:
                found.append(term)
    # de-dup, stable
    seen, out = set(), []
    for x in found:
        k = x.lower()
        if k not in seen:
            seen.add(k); out.append(x)
    return out

# Simple role normaliser: map common aliases -> canonical
_ROLE_ALIASES = {
    "project director": ["programme director","program director","pd","delivery director"],
    "project manager": ["project lead","pm","programme manager","program manager","scrum master"],
    "ops manager":     ["operations manager","operations lead","ops lead","service delivery manager"],
    "team leader":     ["supervisor","team lead","shift lead","coach"],
    "case handler":    ["investigator","analyst","kyc analyst","aml analyst","qa analyst","caseworker"],
    "admin":           ["coordinator","assistant","administrator","pa","ea","office admin"],
}

def load_subject_groups_with_tags(session: Session):
    cats = session.scalars(
        select(TaxonomyCategory).where(TaxonomyCategory.type.in_(["role","subject"]))
        .order_by(TaxonomyCategory.type.asc(), TaxonomyCategory.name.asc())
    ).all()
    out = []
    for c in cats:
        tags = session.scalars(
            select(TaxonomyTag).where(TaxonomyTag.category_id == c.id).order_by(TaxonomyTag.tag.asc())
        ).all()
        if tags:
            out.append((c, tags))
    return out

def _normalise_role(text_lc: str) -> str:
    # direct hit
    for canonical in ROLE_TYPES:
        if canonical.lower() in text_lc:
            return canonical

    # DB + built-ins
    with Session(engine) as s:
        aliases = _load_role_aliases(s)

    for canonical_lc, alias_set in aliases.items():
        for a in alias_set:
            if re.search(r"(?:^|[^A-Za-z0-9])"+re.escape(a)+r"(?:[^A-Za-z0-9]|$)", text_lc):
                # return with ROLE_TYPES' proper case if present; else title-case the canonical
                for r in ROLE_TYPES:
                    if r.lower() == canonical_lc:
                        return r
                return canonical_lc.title()
    return ""

def _latest_doc_for_candidate(session: Session, cand_id: int) -> Optional[Document]:
    return session.scalar(
        select(Document)
        .where(Document.candidate_id == cand_id)
        .order_by(Document.uploaded_at.desc())
    )

def sumsub_sign_request(method: str, path: str, body_str: str = "") -> dict:
    """
    Create Sumsub HMAC signature headers for the given request.
    IMPORTANT: body_str must match the EXACT bytes you send on the wire.
    We therefore JSON-dump with compact separators and send via data=body_str.
    """
    if not SUMSUB_APP_TOKEN or not SUMSUB_SECRET_KEY:
        # Make it obvious why a 500 would occur
        raise RuntimeError("SUMSUB_APP_TOKEN/SUMSUB_SECRET_KEY are not set")

    ts = str(int(time.time()))
    to_sign = f"{ts}{method.upper()}{path}{body_str}".encode("utf-8")
    sig = hmac.new(SUMSUB_SECRET_KEY.encode("utf-8"), to_sign, hashlib.sha256).hexdigest()

    return {
        "X-App-Token": SUMSUB_APP_TOKEN,
        "X-App-Access-Ts": ts,
        "X-App-Access-Sig": sig,
    }

# --- add near other small helpers ---
def _latest_application_for_candidate(session: Session, cand_id: int) -> Optional[Application]:
    return session.scalar(
        select(Application)
        .where(Application.candidate_id == cand_id)
        .order_by(Application.created_at.desc())
    )

# ---------- AI scoring & summarisation ----------

def _tokenize_words(s: str) -> List[str]:
    return re.findall(r"[a-zA-Z]{3,}", (s or "").lower())

def _heuristic_components(job_desc: str, cv_text: str):
    jd_words = set(_tokenize_words(job_desc))
    cv_words = set(_tokenize_words(cv_text))
    if not jd_words or not cv_words:
        return {"score": 0, "overlap": [], "jd_words": 0}
    overlap = sorted(jd_words & cv_words)
    base = min(100, int(100 * len(overlap) / max(10, len(jd_words))))
    return {"score": base, "overlap": overlap[:20], "jd_words": len(jd_words)}

def _jd_completeness_words(job_desc: str) -> Tuple[int, float]:
    wc = len(_tokenize_words(job_desc))
    completeness = max(0.0, min(1.0, wc / 60.0))  # ~1.0 at 60+ words
    return wc, completeness

def _gpt_score_and_rationale(job_desc: str, cv_text: str) -> Tuple[int, List[str]]:
    client = get_openai_client()
    if not client:
        return 0, []
    prompt = f"""
You are an ATS scoring assistant.

Task:
1) Rate the candidate's CV match to the job description on a 0–100 integer scale.
2) Provide exactly 3 short bullets (≤ ~12 words) explaining the score.

Return strictly this JSON (no prose):
{{
  "score": <int 0-100>,
  "bullets": ["...", "...", "..."]
}}

JOB DESCRIPTION:
{job_desc}

CANDIDATE CV:
{cv_text}
"""
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )
        raw = resp.choices[0].message.content.strip()
        import json as _json
        cleaned = re.sub(r"^```json|```$", "", raw).strip()
        data = _json.loads(cleaned)
        g = int(data.get("score", 0))
        bullets = [str(b) for b in (data.get("bullets") or [])][:3]
        return max(0, min(100, g)), bullets
    except Exception as e:
        print("GPT scoring error:", e)
        return 0, []

def ai_score_with_explanation(job_desc: str, cv_text: str) -> Dict:
    heur = _heuristic_components(job_desc, cv_text)
    jd_wc, completeness = _jd_completeness_words(job_desc)
    gpt_score, bullets = _gpt_score_and_rationale(job_desc, cv_text)

    gpt_w = 0.2 + 0.8 * completeness  # rely more on GPT when JD is richer
    heur_w = 1.0 - gpt_w
    blended = int(round(gpt_w * gpt_score + heur_w * heur["score"]))
    if completeness < 0.25:
        blended = min(blended, 88)  # cap if JD is extremely short

    exp_lines = [
        f"JD length: {jd_wc} words (completeness {int(completeness*100)}%).",
        f"Weights → GPT {gpt_w:.2f}, Heuristic {heur_w:.2f}.",
        f"Raw scores → GPT {gpt_score}, Overlap {heur['score']}."
    ]
    if heur["overlap"]:
        exp_lines.append("Top overlaps: " + ", ".join(sorted(heur["overlap"])[:8]) + ".")
    if bullets:
        exp_lines.append("Why: " + " • ".join(bullets))
    explanation = " ".join(exp_lines)

    return {
        "final": blended,
        "gpt": gpt_score,
        "heuristic": heur["score"],
        "jd_words": jd_wc,
        "completeness": completeness,
        "weights": {"gpt": gpt_w, "heuristic": heur_w},
        "overlap": heur["overlap"],
        "bullets": bullets,
        "explanation": explanation,
    }

def _smart_truncate(txt: str, limit: int) -> str:
    """
    Truncate text gracefully at the nearest sentence or word boundary.
    Ensures summaries end cleanly instead of being cut mid-word.
    """
    if len(txt) <= limit:
        return txt
    cut = txt[:limit]
    # Prefer to end on sentence, bullet, or whitespace
    for sep in [". ", "•", "\n", " "]:
        i = cut.rfind(sep)
        if i >= 60:  # ensure we don’t truncate too early
            return cut[:i + 1].rstrip() + " …"
    return cut.rstrip() + " …"

def ai_summarise(text: str, max_chars: int = 1400) -> str:
    text = _truncate_for_ai(text or "", 12000)
    if not text:
        return ""
    client = get_openai_client()
    if client:
        try:
            prompt = (
                "Summarize the candidate’s experience for recruiters in 5–7 bullets. "
                "Keep bullets concise; avoid fluff; focus on impact, domains, tools.\n\n"
                f"TEXT:\n{text}"
            )
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role":"user","content": prompt}],
                temperature=0.2,
            )
            out = (resp.choices[0].message.content or "").strip()
            if out:
                return _smart_truncate(out, max_chars)
        except Exception as e:
            try:
                current_app.logger.exception("ai_summarise OpenAI failed: %s", e)
            except Exception:
                pass
    # Fallback (your existing tidy version)
    import re
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    joined = re.sub(r"\s+", " ", " ".join(lines[:40]))
    bullets = []
    roles = re.findall(
        r"\b[A-Z][a-z]+(?: [A-Z][a-z]+)* (?:Manager|Officer|Analyst|Director|Consultant|Engineer|Lead|Head|Specialist|Advisor|Associate)\b",
        joined,
    )
    roles = list(dict.fromkeys(roles))
    if roles:
        bullets.append("• Experience includes: " + ", ".join(roles[:4]) + (", ..." if len(roles) > 4 else ""))
    bullets.append("• " + joined[:800])
    return _smart_truncate("\n".join(bullets), max_chars)

# --- Optional text extraction deps ---
try:
    from PyPDF2 import PdfReader            # pip install PyPDF2
except Exception:
    PdfReader = None

try:
    import docx                              # python-docx  -> pip install python-docx
except Exception:
    docx = None

try:
    import textract                          # for legacy .doc  -> pip install textract
except Exception:
    textract = None

class RoleTypeForm(FlaskForm):
    name = StringField("Role name", validators=[DataRequired()])
    default_rate = IntegerField("Default £/day", validators=[WTOptional()])
    submit = SubmitField("Add role")

# -------------- Forms --------------
class EngagementForm(FlaskForm):
    name = StringField("Engagement Name", validators=[DataRequired()])
    client = StringField("Client", validators=[WTOptional()])
    # Use text inputs so we can accept DD-MM-YYYY; we’ll parse server-side.
    start_date = StringField("Start Date (DD-MM-YYYY)", validators=[WTOptional()])
    end_date = StringField("End Date (DD-MM-YYYY)", validators=[WTOptional()])
    sow_signed_at = StringField("SOW Signed (DD-MM-YYYY)", validators=[WTOptional()])
    status = SelectField("Status",
                         choices=[("Active","Active"), ("Paused","Paused"), ("Completed","Completed")],
                         validators=[DataRequired()],
                         default="Active")
    description = TextAreaField("Description", validators=[WTOptional()])

class JobForm(FlaskForm):
    engagement_id = SelectField("Engagement", coerce=int, validators=[DataRequired()])
    title = StringField("Job Title", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[DataRequired()])
    role_type = SelectField("Role Type", choices=[(r, r) for r in ROLE_TYPES], validators=[WTOptional()])
    location = StringField("Location", validators=[WTOptional()])
    salary_range = StringField("Salary Range", validators=[WTOptional()])

class ApplyForm(FlaskForm):
    name = StringField("Your Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone", validators=[WTOptional()])
    cover_note = TextAreaField("Cover Note", validators=[WTOptional()])
    cv = FileField("Upload CV (PDF/DOC/DOCX)", validators=[DataRequired()])

class InterviewForm(FlaskForm):
    scheduled_at = DateTimeLocalField("Interview Date & Time", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    interviewer_email = StringField("Interviewer Email", validators=[WTOptional()])

class TaxCategoryForm(FlaskForm):
    type = SelectField("Type", choices=[("role","Role"), ("subject","Subject")], validators=[DataRequired()])
    name = StringField("Category name", validators=[DataRequired()])

class TaxCategoryRenameForm(FlaskForm):
    name = StringField("New name", validators=[DataRequired()])

class TaxTagForm(FlaskForm):
    category_id = SelectField("Category", coerce=int, validators=[DataRequired()])
    tag = StringField("Tag", validators=[DataRequired()])

# ---- Opportunities form ----
class OpportunityForm(FlaskForm):
    name = StringField("Opportunity Name", validators=[DataRequired()])
    client = StringField("Client", validators=[WTOptional()])

    stage = SelectField(
        "Stage",
        choices=[
            ("Lead", "Lead"),
            ("Closed Won", "Closed Won"),
            ("Closed Lost", "Closed Lost"),
        ],
        validators=[DataRequired()],
        default="Lead",
    )

    owner = SelectField("Owner", coerce=int, validators=[WTOptional()])

    # Display as DD-MM-YYYY to the user
    est_start = StringField("Est. Start (DD-MM-YYYY)", validators=[WTOptional()])

    est_value = IntegerField("Est. Value (£)", validators=[WTOptional()])

    notes = TextAreaField("Notes", validators=[WTOptional()])

    # New client contact fields
    client_contact_name  = StringField("Client contact name", validators=[WTOptional()])
    client_contact_role  = StringField("Client contact role", validators=[WTOptional()])
    client_contact_phone = StringField("Client contact phone", validators=[WTOptional()])
    client_contact_email = StringField("Client contact email", validators=[WTOptional(), Email()])

# -------------- Helpers --------------
def allowed_file(fname:str)->bool:
    return "." in fname and fname.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def save_upload(file_storage, subdir="cvs"):
    fname = secure_filename(file_storage.filename)
    if not allowed_file(fname):
        raise ValueError("Unsupported file type")
    new_name = f"{uuid.uuid4()}_{fname}"
    target_dir = os.path.join(app.config["UPLOAD_FOLDER"], subdir)
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, new_name)
    file_storage.save(path)
    return new_name, path, fname

def parse_date(s: Optional[str]):
    if not s:
        return None
    try:
        return dtparser.parse(s).replace(tzinfo=None)
    except Exception:
        return None

def parse_int(s, default=0):
    try:
        return int(str(s).replace(",", "").strip())
    except Exception:
        return default

def currency_fmt(n: int) -> str:
    try:
        return f"£{int(n):,}"
    except Exception:
        return "£0"

def _doc_file_path(doc: "Document") -> str:
    """Absolute path to a stored candidate document."""
    return os.path.join(app.config["UPLOAD_FOLDER"], "cvs", doc.filename)

def _truncate_for_ai(text: str, limit: int = 12000) -> str:
    """Light truncation to keep prompts reasonable."""
    if not text:
        return ""
    t = re.sub(r"\s+\n", "\n", text)
    t = re.sub(r"[ \t]+", " ", t)
    return t[:limit]

def _extract_text_from_pdf(path: str) -> str:
    if PdfReader is None:
        return ""
    try:
        with open(path, "rb") as f:
            reader = PdfReader(f)
            pages = [p.extract_text() or "" for p in reader.pages]
            return "\n".join(pages)
    except Exception as e:
        print("PDF extract error:", e)
        return ""

def _extract_text_from_docx(path: str) -> str:
    if docx is None:
        return ""
    try:
        d = docx.Document(path)
        paras = [p.text for p in d.paragraphs]
        return "\n".join(paras)
    except Exception as e:
        print("DOCX extract error:", e)
        return ""

def _extract_text_from_doc(path: str) -> str:
    """Legacy .doc via textract if available."""
    if textract is None:
        return ""
    try:
        raw = textract.process(path)
        return raw.decode("utf-8", errors="ignore")
    except Exception as e:
        print("DOC extract error:", e)
        return ""

def extract_cv_text_from_doc(path, name=None) -> str:
    """Return plain text from a CV file (pdf/docx/txt). Accepts str or Path."""
    try:
        if not path:
            current_app.logger.warning("CV extract: empty path (name=%r)", name)
            return ""

        p = Path(path) if not isinstance(path, Path) else path

        # If it's a bare filename, resolve to UPLOAD_FOLDER/CV_SUBFOLDER
        if not p.is_absolute():
            root = current_app.config.get("UPLOAD_FOLDER") or os.path.join(current_app.root_path, "uploads")
            cv_sub = current_app.config.get("CV_SUBFOLDER", "cvs")
            p = Path(root) / cv_sub / p

        lname = p.name.lower()

        if not p.exists():
            current_app.logger.error("CV path not found: %s", p)
            return ""

        # Delegate to your existing readers
        if lname.endswith(".pdf"):
            try:
                return read_pdf_text(str(p))  # your existing helper
            except Exception as e:
                current_app.logger.exception("PDF read failed for %r: %s", p, e)
                return ""
        elif lname.endswith(".docx"):
            try:
                return read_docx_text(str(p))  # your existing helper
            except Exception as e:
                current_app.logger.exception("DOCX read failed for %r: %s", p, e)
                return ""
        else:
            try:
                return read_plain_text(str(p))  # your existing helper
            except Exception as e:
                current_app.logger.warning("Plain read failed for %r: %s", p, e)
                return ""

    except Exception as e:
        current_app.logger.exception("CV extract failed for %s: %s", path, e)
        return ""

def extract_cv_text(source) -> str:
    import os
    path = source
    if hasattr(source, "__dict__"):
        path = _doc_file_path(source)

    name = (getattr(source, "original_name", None) or getattr(source, "filename", None) or os.path.basename(str(path) or "")).lower()

    if not path or not os.path.exists(path):
        current_app.logger.warning("CV extract: path not found: %r (name=%r)", path, name)
        return ""

    # DOCX
    if name.endswith(".docx"):
        try:
            import docx
            d = docx.Document(path)
            text = "\n".join(p.text for p in d.paragraphs).strip()
            if text:
                return text
        except Exception as e:
            current_app.logger.exception("DOCX read failed for %r: %s", path, e)

    # PDF
    if name.endswith(".pdf"):
        try:
            import pdfplumber
            with pdfplumber.open(path) as pdf:
                parts = [(p.extract_text() or "") for p in pdf.pages]
            text = "\n".join(parts).strip()
            if text:
                return text
        except Exception as e:
            current_app.logger.exception("PDF read failed for %r: %s", path, e)

    # Plain text fallback
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            t = f.read().strip()
            if t:
                return t
    except Exception as e:
        current_app.logger.warning("Plain read failed for %r: %s", path, e)

    current_app.logger.warning("CV extract: no text extracted from %r", path)
    return ""

# app.py (your extractor)

def extract_cv_text(doc) -> str:
    """
    doc can be a Document row or a filename string.
    Tries DOCX then PDF. Returns '' on failure.
    """
    import logging
    path = _doc_file_path(doc)

    if not os.path.exists(path):
        logging.error("CV path does not exist: %s", path)
        return ""

    # choose by extension
    lower = path.lower()
    try:
        if lower.endswith(".docx"):
            from docx import Document as Docx
            return "\n".join(p.text for p in Docx(path).paragraphs).strip()
        elif lower.endswith(".pdf"):
            import pdfplumber
            text_chunks = []
            with pdfplumber.open(path) as pdf:
                for page in pdf.pages:
                    text_chunks.append(page.extract_text() or "")
            return "\n".join(text_chunks).strip()
        else:
            # fallback: try both
            try:
                from docx import Document as Docx
                return "\n".join(p.text for p in Docx(path).paragraphs).strip()
            except Exception:
                pass
            try:
                import pdfplumber
                text_chunks = []
                with pdfplumber.open(path) as pdf:
                    for page in pdf.pages:
                        text_chunks.append(page.extract_text() or "")
                return "\n".join(text_chunks).strip()
            except Exception:
                pass
            return ""
    except Exception as e:
        logging.exception("CV extract failed for %s: %s", path, e)
        return ""

def extract_cv_text(doc: "Document") -> str:
    """
    Extracts best-effort text from a stored CV Document.
    Supports: .pdf, .docx, .doc (optional via textract).
    """
    if not doc:
        return ""
    path = _doc_file_path(doc)
    ext = os.path.splitext(doc.original_name or doc.filename)[1].lower()

    text = ""
    if ext == ".pdf":
        text = _extract_text_from_pdf(path)
    elif ext == ".docx":
        text = _extract_text_from_docx(path)
    elif ext == ".doc":
        text = _extract_text_from_doc(path)

    # Fallback: try reading as plain text (some users upload .txt with wrong ext)
    if not text:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            pass

    return _truncate_for_ai(text)

def send_email(
    to_email,
    subject,
    html_body,
    attachments: Optional[List[Tuple[str, bytes, str]]] = None,
):
    # Dev / offline mode: if SMTP_HOST is not configured (or just whitespace),
    # don't try to actually send. Just log what would've gone out.
    if not (SMTP_HOST or "").strip():
        print("[DEV] SMTP not configured; would email:")
        print(" To:", to_email)
        print(" Subj:", subject)
        print(" Body:", html_body[:200], "...")
        if attachments:
            for filename, _, mime in attachments:
                print(f" Attachment: {filename} ({mime})")
        return

    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content("This email contains HTML and possibly an ICS invite.")
    msg.add_alternative(html_body, subtype="html")

    if attachments:
        for filename, content, mime in attachments:
            maintype, subtype = mime.split("/", 1)
            msg.add_attachment(
                content,
                maintype=maintype,
                subtype=subtype,
                filename=filename,
            )

    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST.strip(), SMTP_PORT) as server:
        server.starttls(context=context)
        if SMTP_USER and SMTP_PASS:
            server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

# Lightweight stopword set for JD term selection
_STOP = {
    "the","and","for","with","from","into","your","our","you","are","this","that","will","have","has",
    "per","role","job","team","work","working","experience","years","year","etc","such","across","able",
    "strong","good","great","excellent","within","including","include","on","in","of","to","a","an","as",
    "by","is","be","we","they","their","them","it","its","or","not","at","over","under"
}

def _jd_top_terms(job_desc: str, n: int = 8) -> List[str]:
    tokens = _tokenize_words(job_desc)
    freq: Dict[str, int] = {}
    for t in tokens:
        if t in _STOP or len(t) < 3:
            continue
        freq[t] = freq.get(t, 0) + 1
    # rank by frequency then alphabetically for stability
    top = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
    return [w for w, _ in top]

def _cheap_overlap_score(jd_terms: List[str], skills: str) -> int:
    """Very cheap overlap against normalised skills text (no CV parsing)."""
    if not skills:
        return 0
    s = skills.lower()
    hits = sum(1 for t in jd_terms if t and t in s)
    # weight a tiny bit by string length to avoid ties
    return hits * 10 + min(5, len(s) // 2000)

def ics_invite(summary, description, start_dt: datetime.datetime, end_dt: datetime.datetime, location, organizer_email, attendee_email):
    """
    Build a standard .ics invite attachment for email.
    Automatically converts datetimes to UTC if tzinfo is present.
    """
    from email.utils import parseaddr

    # Extract pure email address from “Name <email>” if needed
    organizer_email = parseaddr(organizer_email)[1] or organizer_email
    uid = f"{uuid.uuid4()}@{request.host}".replace(":", "")
    dtfmt = "%Y%m%dT%H%M%SZ"

    def _fmt(dt):
        if not dt:
            return ""
        if dt.tzinfo:
            dt = dt.astimezone(datetime.timezone.utc)
        return dt.strftime(dtfmt)

    start_utc = _fmt(start_dt)
    end_utc = _fmt(end_dt)

    ics = f"""BEGIN:VCALENDAR
PRODID:-//ATS//Interview//EN
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VEVENT
DTSTAMP:{datetime.datetime.utcnow().strftime(dtfmt)}
DTSTART:{start_utc}
DTEND:{end_utc}
SUMMARY:{summary}
UID:{uid}
DESCRIPTION:{description}
ORGANIZER;CN=Talent Ops:MAILTO:{organizer_email}
ATTENDEE;CN=Candidate;RSVP=TRUE:MAILTO:{attendee_email}
LOCATION:{location}
END:VEVENT
END:VCALENDAR
"""
    return ics.encode("utf-8")

# ---- Jinja helpers ----
@app.template_filter("slugify")
def slugify(value: str) -> str:
    s = (value or "").lower().replace(" ", "_")
    return re.sub(r"[^a-z0-9_]", "", s)

def slugify_role(name: str) -> str:
    s = (name or "").lower().replace(" ", "_")
    return re.sub(r"[^a-z0-9_]", "", s)

# -------------- Routes --------------
from sqlalchemy.orm import selectinload  # make sure this import exists

# Health check endpoint (no DB required)
@app.route("/health")
def health():
    """Simple health check endpoint for Railway"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }), 200

@app.route("/")
def index():
    now = datetime.datetime.utcnow()
    d7  = now - datetime.timedelta(days=7)
    d30 = now - datetime.timedelta(days=30)
    d3  = now - datetime.timedelta(days=3)

    with Session(engine) as s:
        # Basic KPIs
        total_candidates = s.scalar(select(func.count(Candidate.id))) or 0
        total_apps = s.scalar(select(func.count(Application.id))) or 0
        interviews = s.scalar(
            select(func.count()).select_from(Application).where(Application.status == "Interview")
        ) or 0
        onboarding = s.scalar(
            select(func.count()).select_from(Application).where(Application.status == "Onboarding")
        ) or 0

        active_engagements = s.scalars(
            select(Engagement).where(Engagement.status == "Active")
        ).all()

        # Eager-load engagement so templates can safely access j.engagement.name
        recent_jobs = s.scalars(
            select(Job)
            .options(selectinload(Job.engagement))
            .order_by(Job.created_at.desc())
            .limit(5)
        ).all()

        # Resource pool trend
        new_candidates_7  = s.scalar(select(func.count(Candidate.id)).where(Candidate.created_at >= d7)) or 0
        new_candidates_30 = s.scalar(select(func.count(Candidate.id)).where(Candidate.created_at >= d30)) or 0
        new_docs_7  = s.scalar(select(func.count(Document.id)).where(Document.uploaded_at >= d7)) or 0
        new_docs_30 = s.scalar(select(func.count(Document.id)).where(Document.uploaded_at >= d30)) or 0

        # Upcoming interviews (next 7 days)
        upcoming_interviews = s.execute(
            select(Application, Candidate, Job)
            .join(Candidate, Candidate.id == Application.candidate_id)
            .join(Job, Job.id == Application.job_id)
            .where(Application.interview_scheduled_at != None)
            .where(Application.interview_scheduled_at >= now)
            .where(Application.interview_scheduled_at <= now + datetime.timedelta(days=7))
            .order_by(Application.interview_scheduled_at.asc())
            .limit(10)
        ).all()

        # Contracts sent but not signed after 3 days
        unsigned_contracts = s.execute(
            select(ESigRequest, Application, Candidate, Job)
            .join(Application, Application.id == ESigRequest.application_id)
            .join(Candidate, Candidate.id == Application.candidate_id)
            .join(Job, Job.id == Application.job_id)
            .where(func.lower(ESigRequest.status).in_(["sent", "delivered"]))
            .where(ESigRequest.sent_at != None)
            .where(ESigRequest.sent_at < d3)
            .order_by(ESigRequest.sent_at.asc())
            .limit(10)
        ).all()

        # TrustID in progress > 3 days
        vetting_in_progress = s.execute(
            select(TrustIDCheck, Application, Candidate, Job)
            .join(Application, Application.id == TrustIDCheck.application_id)
            .join(Candidate, Candidate.id == Application.candidate_id)
            .join(Job, Job.id == Application.job_id)
            .where(TrustIDCheck.status.in_(["Created", "InProgress"]))
            .order_by(TrustIDCheck.id.desc())
        ).all()

        # Stuck apps
        stuck_apps = s.execute(
            select(Application, Candidate, Job)
            .join(Candidate, Candidate.id == Application.candidate_id)
            .join(Job, Job.id == Application.job_id)
            .where(Application.created_at < d7)
            .where(Application.status.in_(["New", "Screening", "Interview"]))
            .order_by(Application.created_at.asc())
            .limit(10)
        ).all()

        # Engagement progress tiles
        plan_rows = s.execute(
            select(EngagementPlan.engagement_id, func.sum(EngagementPlan.planned_count))
            .group_by(EngagementPlan.engagement_id)
        ).all()
        planned_map = {eng_id: int(cnt or 0) for eng_id, cnt in plan_rows}

        signed_rows = s.execute(
            select(Engagement.id, func.count(ESigRequest.id))
            .select_from(Engagement)
            .join(Job, Job.engagement_id == Engagement.id, isouter=True)
            .join(Application, Application.job_id == Job.id, isouter=True)
            .join(ESigRequest, ESigRequest.application_id == Application.id, isouter=True)
            .where(func.lower(ESigRequest.status).in_(["signed", "completed"]))
            .group_by(Engagement.id)
        ).all()
        signed_map = {eng_id: int(cnt or 0) for eng_id, cnt in signed_rows}

        engagement_progress = []
        for e in active_engagements:
            planned = planned_map.get(e.id, 0)
            signed = signed_map.get(e.id, 0)
            pct = int(100 * signed / planned) if planned else 0
            engagement_progress.append((e, planned, signed, pct))
        engagement_progress.sort(key=lambda t: t[3])

    return render_template(
        "dashboard.html",
        total_candidates=total_candidates,
        total_apps=total_apps,
        interviews=interviews,
        onboarding=onboarding,
        active_engagements=active_engagements,
        recent_jobs=recent_jobs,
        new_candidates_7=new_candidates_7,
        new_candidates_30=new_candidates_30,
        new_docs_7=new_docs_7,
        new_docs_30=new_docs_30,
        upcoming_interviews=upcoming_interviews,
        unsigned_contracts=unsigned_contracts,
        vetting_in_progress=vetting_in_progress,
        stuck_apps=stuck_apps,
        engagement_progress=engagement_progress,
    )

@app.post("/action/score_candidate/<int:cand_id>", endpoint="action_score_candidate_v2")
def action_score_candidate_v2(cand_id: int):
    """
    Recalculate AI match score for a candidate against a job.
    Accepts job_id in form/query; if missing, falls back to latest application.job_id.
    """
    j = request.form.get("job_id") or request.args.get("job_id")
    try:
        job_id = int(j) if j else 0
    except Exception:
        job_id = 0

    from sqlalchemy import select
    from sqlalchemy.orm import Session as SASession

    with SASession(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            flash("Candidate not found.", "warning")
            return redirect(url_for("resource_pool"))

        # Latest application (for fallback + write-back)
        latest_app = s.execute(
            select(Application)
            .where(Application.candidate_id == cand_id)
            .order_by(Application.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()

        # Fallback job_id from latest application if not provided
        if not job_id and latest_app and getattr(latest_app, "job_id", None):
            job_id = int(latest_app.job_id or 0)

        if not job_id:
            flash("Missing job id for scoring.", "warning")
            return redirect(url_for("candidate_profile", cand_id=cand_id))

        job = s.get(Job, job_id)
        if not job:
            flash("Job not found.", "warning")
            return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=job_id))

        # Find the most recent CV
        order_col = getattr(Document, "uploaded_at", Document.id)
        doc = s.execute(
            select(Document)
            .where(Document.candidate_id == cand_id,
                   getattr(Document, "doc_type", Document.doc_type) == "cv")
            .order_by(order_col.desc())
            .limit(1)
        ).scalar_one_or_none()

        if not doc:
            flash("No CV found for this candidate.", "warning")
            return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=job_id))

        # Extract text using the new helper
        cv_text = extract_cv_text_from_doc(doc, name=getattr(cand, "name", None)) or ""
        if not cv_text.strip():
            flash("Could not read the CV to score.", "warning")
            return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=job_id))

        # Score + write-back
        wrote = False
        try:
            payload = ai_score_with_explanation(job.description or "", cv_text) or {}
            score = _pick_ai_score(payload)

            if latest_app is not None and hasattr(latest_app, "ai_score"):
                latest_app.ai_score = score
                wrote = True

            if hasattr(cand, "ai_score"):
                cand.ai_score = score
                wrote = True

            if latest_app is not None and hasattr(latest_app, "ai_explanation"):
                latest_app.ai_explanation = (payload.get("explanation") or "")[:7999]
        except Exception as e:
            current_app.logger.exception("ai_score_with_explanation failed: %s", e)

        if wrote:
            s.commit()

    flash("AI score recalculated.", "success")
    return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=job_id))

# --- SHORTLIST INSERT GUARD (put this *after* models are imported/declared) ---
from sqlalchemy import event
from sqlalchemy.orm import Session as SASession
from flask import g

@event.listens_for(SASession, "before_flush")
def _prevent_auto_shortlist(session, flush_context, instances):
    """
    Block implicit/accidental Shortlist inserts by removing them from the unit-of-work
    unless the handler explicitly enabled it via g.allow_shortlist = True.
    This avoids raising inside the transaction.
    """
    try:
        allow = bool(getattr(g, "allow_shortlist", False))
    except Exception:
        # outside request context (CLI, shell, migrations): allow
        allow = True

    if allow:
        return

    # remove any newly-added Shortlist objects quietly
    for obj in list(session.new):
        if isinstance(obj, Shortlist):
            session.expunge(obj)

@app.post("/action/score/<int:cand_id>")
def action_score_legacy(cand_id: int):
    # Reuse the v2 scorer (it now infers job_id if missing)
    return action_score_candidate_v2(cand_id)

@app.post("/action/score/application/<int:app_id>")
def action_score_from_application(app_id: int):
    from sqlalchemy import select
    from sqlalchemy.orm import Session as SASession
    with SASession(engine) as s:
        app = s.get(Application, app_id)
        if not app:
            flash("Application not found.", "warning")
            return redirect(url_for("dashboard"))
        # Call the same scorer; it will find the CV and write back to this app
        with current_app.test_request_context(
            f"/action/score/{app.candidate_id}?job_id={app.job_id}", method="POST"
        ):
            return action_score_candidate_v2(app.candidate_id)

# ---- Opportunities: list + create ----
@app.route("/opportunities", methods=["GET", "POST"])
def opportunities_():
    with Session(engine) as s:
        # pull users for the "Owner" dropdown
        users_rows = s.execute(
            text("SELECT id, name FROM users ORDER BY name ASC")
        ).all()

    # build the form *after* we have users
    form = OpportunityForm()
    form.owner.choices = [(u[0], u[1]) for u in users_rows]  # (id, display)

    if form.validate_on_submit():
        # Parse DD-MM-YYYY to datetime (UK style)
        raw_start = form.est_start.data or ""
        est_start_dt = parse_date_dmy(raw_start)

        # est_value is already numeric (IntegerField), but could be None
        val = form.est_value.data if form.est_value.data is not None else 0

        # map owner_id -> friendly owner name
        owner_name = ""
        if form.owner.data:
            # form.owner.data is the user_id (int)
            with Session(engine) as s:
                row = s.execute(
                    text("SELECT name FROM users WHERE id=:i"),
                    {"i": form.owner.data},
                ).first()
                if row:
                    owner_name = row[0] or ""

        with Session(engine) as s:
            opp = Opportunity(
                name=form.name.data,
                client=form.client.data or "",
                stage=form.stage.data,
                owner=owner_name,  # storing name for now
                est_start=est_start_dt,
                est_value=int(val or 0),
                # we keep probability in db but we no longer ask user for it,
                # so default to 0 for new Leads, 100 for Closed Won, 0 for Closed Lost
                probability=100 if form.stage.data.lower() == "closed won" else 0,
                notes=form.notes.data or "",
                client_contact_name=form.client_contact_name.data or "",
                client_contact_role=form.client_contact_role.data or "",
                client_contact_phone=form.client_contact_phone.data or "",
                client_contact_email=form.client_contact_email.data or "",
            )
            s.add(opp)
            s.flush()  # now opp.id exists

            # if they immediately saved it as Closed Won, auto-create engagement
            if (opp.stage or "").strip().lower() == "closed won":
                e = create_engagement_for_opportunity(s, opp)
                if e:
                    flash(f"Engagement {e.ref} created from Closed Won opportunity.", "success")

            s.commit()

        flash("Opportunity created", "success")
        return redirect(url_for("opportunities_"))

    # GET render
    with Session(engine) as s:
        rows = s.scalars(
            select(Opportunity).order_by(Opportunity.created_at.desc())
        ).all()

        # Attach engagement links just like before
        eng_links = {
            oid: (eid, ref)
            for (eid, ref, oid) in s.execute(
                text("SELECT id, ref, opportunity_id FROM engagements WHERE opportunity_id IS NOT NULL")
            ).all()
        }
        for o in rows:
            tup = eng_links.get(o.id)
            if tup:
                o._engagement_id, o._engagement_ref = tup[0], tup[1]
            else:
                o._engagement_id = None
                o._engagement_ref = None

    # We are intentionally NOT calculating pipeline tiles anymore
    return render_template(
        "opportunities_.html",
        form=form,
        items=rows,
    )

@app.route("/admin/roles", methods=["GET", "POST"])
def admin_roles():
    form = RoleTypeForm()
    with Session(engine) as s:
        if form.validate_on_submit():
            rt = RoleType(
                name=form.name.data.strip(),
                default_rate=int(form.default_rate.data or 0),
            )
            try:
                s.add(rt)
                s.commit()
                flash("Role added", "success")
            except IntegrityError:
                s.rollback()
                flash("That role already exists", "warning")

        roles = s.scalars(
            select(RoleType).order_by(RoleType.name.asc())
        ).all()

    return render_template("admin_roles.html", form=form, roles=roles)

@app.route("/sumsub/access_token/<external_user_id>", methods=["POST", "GET"])
def sumsub_access_token(external_user_id: str):
    """
    Generate a temporary access token for Sumsub WebSDK Next.
    Works with both GET and POST for easy testing.

    Query params:
      - ttlInSecs (default 600)
      - levelName (optional but recommended; e.g. 'id-and-liveness' or 'basic-kyb-level')
    """
    try:
        ttl = request.args.get("ttlInSecs", "600")
        level_name = (request.args.get("levelName") or "").strip()

        from urllib.parse import quote_plus as q
        path = f"/resources/accessTokens?userId={q(external_user_id)}&ttlInSecs={q(ttl)}"
        if level_name:
            path += f"&levelName={q(level_name)}"

        headers = sumsub_sign_request("POST", path, "")
        resp = requests.post(f"{SUMSUB_BASE_URL}{path}", headers=headers, timeout=15)

        content_type = (resp.headers.get("Content-Type") or "")
        if "application/json" in content_type.lower():
            return jsonify(resp.json()), resp.status_code
        return (resp.text, resp.status_code, {"Content-Type": "text/plain; charset=utf-8"})
    except Exception as e:
        current_app.logger.exception("Sumsub access token failed")
        return jsonify({"error": "sumsub_access_token_failed", "detail": str(e)}), 500

@app.route("/sumsub/create_applicant", methods=["POST"])
def sumsub_create_applicant():
    """
    Create a new Sumsub applicant.

    Send JSON:
      {
        "externalUserId": "test_user_001",
        "levelName": "id-and-liveness"   # optional; falls back to env SUMSUB_LEVEL_NAME or first available
      }

    Notes:
    - Sumsub requires `levelName` in the QUERY STRING (and included in the signature).
    - We validate levelName against your account’s levels and set the correct applicant type.
    """
    from urllib.parse import quote_plus

    try:
        data = request.get_json(silent=True) or {}
        external_user_id = (data.get("externalUserId") or f"user_{int(time.time())}").strip()
        requested_level = (data.get("levelName") or os.getenv("SUMSUB_LEVEL_NAME", "")).strip()

        # ---- 1) Fetch levels from Sumsub and validate ----
        levels_path = "/resources/applicants/-/levels"
        lv_headers = sumsub_sign_request("GET", levels_path, "")
        lv_resp = requests.get(f"{SUMSUB_BASE_URL}{levels_path}", headers=lv_headers, timeout=15)

        levels_json = {}
        try:
            levels_json = lv_resp.json() if lv_resp.headers.get("Content-Type","").lower().startswith("application/json") else {}
        except Exception:
            levels_json = {}

        # Normalise to a simple list of dicts with 'name' & 'applicantType'
        items = []
        if isinstance(levels_json, dict) and "list" in levels_json and isinstance(levels_json["list"], dict):
            items = levels_json["list"].get("items", []) or []
        elif isinstance(levels_json, dict) and "items" in levels_json:
            items = levels_json.get("items", []) or []

        available = [(it.get("name"), (it.get("applicantType") or it.get("type") or "individual")) for it in items if it.get("name")]
        available_names = [n for n, _ in available]

        # If no requested level, pick first available
        if not requested_level:
            if not available_names:
                return jsonify({
                    "error": "sumsub_create_applicant_failed",
                    "detail": "No levels available in your Sumsub project. Create a level in the Sumsub dashboard first."
                }), 400
            requested_level = available_names[0]

        # Validate requested level
        match = None
        for n, a_type in available:
            if n == requested_level:
                match = (n, a_type)
                break

        if not match:
            return jsonify({
                "error": "invalid_level_name",
                "detail": f"Level '{requested_level}' not found.",
                "availableLevels": available_names
            }), 400

        level_name, applicant_type = match  # applicant_type: 'individual' or 'company'

        # ---- 2) Build payload with the correct applicant type ----
        payload = {
            "externalUserId": external_user_id,
            "type": "company" if str(applicant_type).lower() == "company" else "individual"
        }
        body_str = json.dumps(payload, separators=(",", ":"))

        # ---- 3) Call Sumsub create with levelName in query (and sign including the query) ----
        q_level = quote_plus(level_name)
        path = f"/resources/applicants?levelName={q_level}"

        headers = sumsub_sign_request("POST", path, body_str)
        headers["Content-Type"] = "application/json"

        resp = requests.post(
            f"{SUMSUB_BASE_URL}{path}",
            data=body_str,  # send EXACT bytes we signed
            headers=headers,
            timeout=20,
        )

        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype and (resp.text or "").strip():
            try:
                return jsonify(resp.json()), resp.status_code
            except Exception:
                pass

        # Always return a JSON summary for non-JSON/empty bodies
        return jsonify({
            "status": resp.status_code,
            "reason": resp.reason,
            "headers": dict(resp.headers or {}),
            "text": (resp.text or "").strip()
        }), resp.status_code

    except Exception as e:
        current_app.logger.exception("Sumsub create_applicant failed")
        return jsonify({"error": "sumsub_create_applicant_failed", "detail": str(e)}), 500

@app.route("/__ping")
def __ping():
    return jsonify({
        "ok": True,
        "loaded_from": __file__,
        "has_sumsub_create": "sumsub_create_applicant" in current_app.view_functions,
        "routes_count": len(list(current_app.url_map.iter_rules())),
    })

@app.route("/__routes")
def __routes():
    routes = []
    for r in current_app.url_map.iter_rules():
        routes.append({
            "rule": str(r),
            "endpoint": r.endpoint,
            "methods": sorted(m for m in r.methods if m not in {"HEAD", "OPTIONS"}),
        })
    # sort for readability
    routes.sort(key=lambda x: x["rule"])
    return jsonify({"routes": routes})

@app.route("/sumsub/levels", methods=["GET"])
def sumsub_list_levels():
    """
    Lists all verification levels available in your Sumsub project.
    """
    try:
        path = "/resources/applicants/-/levels"
        headers = sumsub_sign_request("GET", path, "")
        resp = requests.get(f"{SUMSUB_BASE_URL}{path}", headers=headers, timeout=15)

        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype and (resp.text or "").strip():
            return jsonify(resp.json()), resp.status_code

        # Always return JSON, even if Sumsub sends text/empty
        return jsonify({
            "status": resp.status_code,
            "reason": resp.reason,
            "headers": dict(resp.headers or {}),
            "text": (resp.text or "").strip()
        }), resp.status_code

    except Exception as e:
        current_app.logger.exception("Sumsub list levels failed")
        return jsonify({"error": "sumsub_list_levels_failed", "detail": str(e)}), 500

# --- Sumsub WebSDK launcher page ---
@app.route("/sumsub/start/<external_user_id>", methods=["GET"])
def sumsub_start(external_user_id: str):
    """
    Simple page that hosts Sumsub WebSDK for a given externalUserId.
    Query params (all optional):
      ttlInSecs   -> defaults 600
      levelName   -> if omitted, we’ll pass nothing (Sumsub falls back to applicant's level)
      theme       -> 'light' or 'dark' (default 'light')
      lang        -> 'en' by default
    """
    try:
        ttl = int(request.args.get("ttlInSecs") or 600)
    except Exception:
        ttl = 600

    level_name = (request.args.get("levelName") or os.getenv("SUMSUB_LEVEL_NAME", "")).strip()
    theme      = (request.args.get("theme") or "light").strip() or "light"
    lang       = (request.args.get("lang") or "en").strip() or "en"

    # Nice label in the header so you know you’re on sandbox
    label = "Sumsub Sandbox" if "sandbox" in (SUMSUB_BASE_URL or "").lower() else "Sumsub"

    return render_template(
        "sumsub_start.html",
        external_user_id=external_user_id,
        ttl=ttl,
        level_name=level_name,
        theme=theme,
        lang=lang,
        sumsub_label=label,
    )

@app.route("/sumsub/applicant/<applicant_id>", methods=["GET"])
def sumsub_get_applicant(applicant_id: str):
    """Fetch applicant object from Sumsub."""
    try:
        path = f"/resources/applicants/{applicant_id}"
        headers = sumsub_sign_request("GET", path, "")
        resp = requests.get(f"{SUMSUB_BASE_URL}{path}", headers=headers, timeout=15)

        content_type = (resp.headers.get("Content-Type") or "")
        if "application/json" in content_type.lower():
            return jsonify(resp.json()), resp.status_code
        else:
            return (resp.text, resp.status_code, {"Content-Type": "text/plain; charset=utf-8"})
    except Exception as e:
        current_app.logger.exception("Sumsub get applicant failed")
        return jsonify({"error": "sumsub_get_applicant_failed", "detail": str(e)}), 500

# --- Convert Opportunity → Engagement ---
@app.route("/opportunities/<int:opp_id>/convert", methods=["POST"], endpoint="opportunity_convert_v2")
def opportunity_convert_v2(opp_id):
    with Session(engine) as s:
        opp = s.get(Opportunity, opp_id)
        if not opp:
            abort(404)

        # only Closed Won can convert
        if (opp.stage or "").lower() != "closed won":
            flash("Only Closed Won opportunities can be converted.", "warning")
            return redirect(url_for("opportunities_"))

        # already converted?
        existing = s.scalar(select(Engagement).where(Engagement.opportunity_id == opp.id))
        if existing:
            flash(f"Engagement {existing.ref or existing.id} already exists.", "info")
            return redirect(url_for("engagement_dashboard", eng_id=existing.id))

        e = create_engagement_for_opportunity(s, opp)
        s.commit()
        flash(f"Engagement {e.ref or e.id} created.", "success")
        return redirect(url_for("engagement_dashboard", eng_id=e.id))

@app.route("/opportunity/<int:opp_id>/convert_to_engagement", methods=["POST"])
def opportunity_convert_to_engagement(opp_id):
    with Session(engine) as s:
        opp = s.get(Opportunity, opp_id)
        if not opp:
            abort(404)
        if (opp.stage or "").lower() != "closed won":
            flash("Only Closed Won opportunities can be converted.", "warning")
            return redirect(url_for("opportunity_edit", opp_id=opp_id))

        eng = _create_engagement_from_opportunity(s, opp)
        s.commit()
        flash(f"Engagement {eng.ref} created.", "success")
        return redirect(url_for("engagement_dashboard", eng_id=eng.id))

@app.route("/admin/opportunities/backfill_engagements", methods=["POST"])
def backfill_engagements_for_won():
    created = 0
    with Session(engine) as s:
        won = s.scalars(select(Opportunity).where(Opportunity.stage=="Closed Won")).all()
        for opp in won:
            e = s.scalar(select(Engagement).where(Engagement.opportunity_id==opp.id))
            if not e:
                _create_engagement_from_opportunity(s, opp)
                created += 1
        s.commit()
    flash(f"Created {created} engagements from Closed Won opportunities.", "success")
    return redirect(url_for("opportunities_"))

# ---- Opportunities: edit ----
@app.route("/opportunity/<int:opp_id>", methods=["GET", "POST"])
def opportunity_edit(opp_id):
    # Load the opportunity row
    with Session(engine) as s:
        opp = s.scalar(select(Opportunity).where(Opportunity.id == opp_id))
        if not opp:
            abort(404)

        # Load owners for dropdown
        users_rows = s.execute(
            text("SELECT id, name FROM users ORDER BY name ASC")
        ).all()
        choices = [(u[0], u[1]) for u in users_rows]

        # We'll need to map owner name -> id for initial form data
        owner_id_for_form = None
        if opp.owner:
            for uid, uname in choices:
                if (uname or "").strip() == (opp.owner or "").strip():
                    owner_id_for_form = uid
                    break

        # Prefill form
        form = OpportunityForm(
            name=opp.name,
            client=opp.client,
            stage=opp.stage,
            owner=owner_id_for_form,
            est_start=format_date_dmy(opp.est_start),  # "DD-MM-YYYY"
            est_value=opp.est_value or 0,
            notes=opp.notes or "",
            client_contact_name = opp.client_contact_name or "",
            client_contact_role = opp.client_contact_role or "",
            client_contact_phone = opp.client_contact_phone or "",
            client_contact_email = opp.client_contact_email or "",
        )
        form.owner.choices = choices

        if form.validate_on_submit():
            prev_stage = (opp.stage or "").strip().lower()

            # Map owner dropdown (user id) back to owner name string for storage
            new_owner_name = ""
            if form.owner.data:
                row = s.execute(
                    text("SELECT name FROM users WHERE id=:i"),
                    {"i": form.owner.data},
                ).first()
                if row:
                    new_owner_name = row[0] or ""

            opp.name = form.name.data
            opp.client = form.client.data or ""
            opp.stage = form.stage.data
            opp.owner = new_owner_name
            opp.est_start = parse_date_dmy(form.est_start.data)
            opp.est_value = int(form.est_value.data or 0)

            # probability is now implicit; we keep writing it for downstream logic
            opp.probability = 100 if (opp.stage or "").strip().lower() == "closed won" else 0

            opp.notes = form.notes.data or ""

            opp.client_contact_name  = form.client_contact_name.data  or ""
            opp.client_contact_role  = form.client_contact_role.data  or ""
            opp.client_contact_phone = form.client_contact_phone.data or ""
            opp.client_contact_email = form.client_contact_email.data or ""

            # If it becomes Closed Won, create/link an engagement (idempotent)
            new_stage = (opp.stage or "").strip().lower()
            e = None
            if new_stage == "closed won" and prev_stage != "closed won":
                e = create_engagement_for_opportunity(s, opp)

            # Also handle the case where it was already Closed Won but not linked yet
            if new_stage == "closed won" and not e:
                e = create_engagement_for_opportunity(s, opp)

            s.commit()
            flash("Opportunity updated", "success")

            if e:
                flash(f"Engagement {e.ref} created.", "success")
                return redirect(url_for("engagement_dashboard", eng_id=e.id))

            return redirect(url_for("opportunities_"))

    return render_template("opportunity_edit.html", form=form, opp=opp)

@app.route(
    "/action/onboarding_email/<int:app_id>",
    methods=["POST"],
    endpoint="action_onboarding_email"
)
def action_onboarding_email(app_id):
    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id == app_id))
        if not appn:
            abort(404)

        cand = s.scalar(select(Candidate).where(Candidate.id == appn.candidate_id))
        job  = s.scalar(select(Job).where(Job.id == appn.job_id))

        link = f"{APP_BASE_URL}/application/{appn.id}"
        html = f"""
        <h3>Welcome to onboarding</h3>
        <p>Hi {cand.name}, thanks for applying for <b>{job.title}</b>. We'll guide you through vetting next.</p>
        <p>You can check status here: <a href="{link}">{link}</a></p>
        """

        # Send email (no-op in dev if SMTP_* not configured)
        send_email(cand.email, f"Onboarding for {job.title}", html)

        # Update flags
        appn.onboarding_email_sent = True
        appn.status = "Onboarding"
        s.commit()

    flash("Onboarding email sent", "success")
    return redirect(url_for("application_detail", app_id=app_id))

@app.route("/kanban")
def kanban():
    columns = ["New","Screening","Interview","Offer","Onboarding","Hired","Rejected"]
    with Session(engine) as s:
        data = {col: s.execute(select(Application, Candidate, Job)
                               .join(Candidate, Candidate.id==Application.candidate_id)
                               .join(Job, Job.id==Application.job_id)
                               .where(Application.status==col)
                               .order_by(Application.created_at.desc())
                               ).all() for col in columns}
    return render_template("kanban.html", columns=columns, data=data)

@app.route("/kanban/move", methods=["POST"])
def kanban_move():
    payload = request.json or {}
    app_id = int(payload.get("app_id"))
    new_status = payload.get("new_status")
    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id==app_id))
        if not appn:
            abort(404)
        appn.status = new_status
        s.commit()
    return jsonify({"ok": True})

@app.route("/engagements/create", methods=["GET", "POST"])
def create_engagement():
    form = EngagementForm()
    if form.validate_on_submit():
        with Session(engine) as s:
            # allocate sequential EG### reference
            new_ref = _next_engagement_ref(s)

            e = Engagement(
                ref=new_ref,                                     # NEW
                name=form.name.data,
                client=form.client.data or "",
                status=form.status.data or "Active",
                start_date=parse_date_dmy(form.start_date.data), # DD-MM-YYYY
                end_date=parse_date_dmy(form.end_date.data),     # DD-MM-YYYY
                sow_signed_at=parse_date_dmy(form.sow_signed_at.data),
                description=form.description.data or "",
            )
            s.add(e)
            s.commit()
            flash(f"Engagement {e.ref} created", "success")
        return redirect(url_for("engagements"))
    return render_template("create_engagement.html", form=form)

@app.route("/engagements", methods=["GET"])
def engagements():
    with Session(engine) as s:
        # 1. Current engagements (for "Current Engagements" table)
        engagements_rows = s.scalars(
            select(Engagement).order_by(Engagement.id.desc())
        ).all()

        # 2. All opportunities, newest first
        opp_rows = s.scalars(
            select(Opportunity).order_by(Opportunity.created_at.desc())
        ).all()

        # 3. Map opportunity.id -> (engagement_id, engagement_ref)
        eng_links = {
            oid: (eid, ref)
            for (eid, ref, oid) in s.execute(
                text(
                    "SELECT id, ref, opportunity_id "
                    "FROM engagements "
                    "WHERE opportunity_id IS NOT NULL"
                )
            ).all()
        }

        # 4. Annotate each opportunity with the linked engagement (if any)
        for o in opp_rows:
            tup = eng_links.get(o.id)
            if tup:
                o._engagement_id, o._engagement_ref = tup[0], tup[1]
            else:
                o._engagement_id = None
                o._engagement_ref = None

        # 5. Filter out opportunities that are already active engagements
        #    Rule: hide if stage == "closed won" (case-insensitive)
        #    AND we already have an engagement for it.
        visible_opps = []
        for o in opp_rows:
            st_low = (o.stage or "").strip().lower()
            already_converted = bool(o._engagement_id)
            is_closed_won = (st_low == "closed won")
            if is_closed_won and already_converted:
                # skip, it'll show up in Current Engagements
                continue
            visible_opps.append(o)

    return render_template(
        "engagements.html",
        items=engagements_rows,
        opps=visible_opps,
    )

@app.route("/jobs", methods=["GET","POST"])
def jobs():
    # If coming from an engagement, lock to it
    eng_id_lock = request.args.get("eng_id", type=int)

    with Session(engine) as s:
        # Validate the lock id (if provided)
        locked_eng = None
        if eng_id_lock:
            locked_eng = s.get(Engagement, eng_id_lock)
            if not locked_eng:
                flash("Engagement not found for the requested job context.", "warning")
                return redirect(url_for("engagements"))

        # Build the form
        form = JobForm()

        if locked_eng:
            # Only one choice, preselected — include the engagement reference in the label
            form.engagement_id.choices = [
                (locked_eng.id, f"{locked_eng.ref or '—'} · {locked_eng.name} ({locked_eng.client})")
            ]
            form.engagement_id.data = locked_eng.id  # prefill
        else:
            # Global selector — include refs for all items
            engagements = s.scalars(select(Engagement).order_by(Engagement.id.desc())).all()
            form.engagement_id.choices = [
                (e.id, f"{e.ref or '—'} · {e.name} ({e.client})") for e in engagements
            ]

        # Create
        if form.validate_on_submit():
            engagement_id_final = locked_eng.id if locked_eng else form.engagement_id.data
            j = Job(
                engagement_id=engagement_id_final,
                title=form.title.data,
                description=form.description.data,
                role_type=form.role_type.data or "",
                location=form.location.data or "",
                salary_range=form.salary_range.data or "",
            )
            s.add(j)
            s.commit()
            flash("Job created", "success")

            # After creating in a locked context, bounce back to that engagement’s dashboard
            if locked_eng:
                return redirect(url_for("engagement_job_detail", eng_id=locked_eng.id, job_id=j.id))
            return redirect(url_for("jobs"))

        # List jobs (optionally filtered to the locked engagement for clarity)
        if locked_eng:
            rows = s.scalars(
                select(Job)
                .where(Job.engagement_id == locked_eng.id)
                .options(selectinload(Job.engagement))
                .order_by(Job.created_at.desc())
            ).all()
        else:
            rows = s.scalars(
                select(Job)
                .options(selectinload(Job.engagement))
                .order_by(Job.created_at.desc())
            ).all()

    return render_template(
        "jobs.html",
        form=form,
        items=rows,
        locked_engagement=locked_eng,  # pass for UX banner/disable
    )

@app.route("/job/<token>")
def public_job(token):
    with Session(engine) as s:
        job = s.scalar(select(Job).where(Job.public_token==token))
        if not job:
            abort(404)
    return render_template("public_job.html", job=job)

@app.route("/job/new", methods=["GET", "POST"])
def job_new():
    """Create a new job post."""
    from sqlalchemy.orm import Session
    with Session(engine) as s:
        if request.method == "POST":
            title = request.form.get("title") or "Untitled Job"
            role = request.form.get("role") or ""
            description = request.form.get("description") or ""
            status = request.form.get("status") or "Open"
            engagement_id = request.form.get("engagement_id") or None

            job = Job(
                title=title,
                role=role,
                description=description,
                status=status,
                engagement_id=engagement_id,
                created_at=datetime.utcnow(),
            )
            s.add(job)
            s.commit()
            flash("Job created successfully.", "success")
            return redirect(url_for("engagement_dashboard", eng_id=engagement_id or 1))

        # GET request
        roles = s.scalars(select(Role).order_by(Role.name.asc())).all() if "Role" in globals() else []
        return render_template("job_form.html", job=None, roles=roles, mode="create")


@app.route("/job/<int:job_id>/edit", methods=["GET", "POST"])
def job_edit(job_id):
    """Edit an existing job post."""
    from sqlalchemy.orm import Session
    with Session(engine) as s:
        job = s.get(Job, job_id)
        if not job:
            flash("Job not found.", "warning")
            return redirect(url_for("engagements"))

        if request.method == "POST":
            job.title = request.form.get("title") or job.title
            job.role = request.form.get("role") or job.role
            job.description = request.form.get("description") or job.description
            job.status = request.form.get("status") or job.status
            s.commit()
            flash("Job updated successfully.", "success")
            return redirect(url_for("engagement_dashboard", eng_id=job.engagement_id or 1))

        roles = s.scalars(select(Role).order_by(Role.name.asc())).all() if "Role" in globals() else []
        return render_template("job_form.html", job=job, roles=roles, mode="edit")

@app.route("/apply/<token>", methods=["GET", "POST"])
def apply(token):
    form = ApplyForm()
    with Session(engine) as s:
        job = s.scalar(select(Job).where(Job.public_token == token))
        if not job:
            abort(404)

        if form.validate_on_submit():
            # 1) Candidate (dedupe by email)
            raw_email  = form.email.data or ""
            norm_email = raw_email.strip().lower()

            cand = s.scalar(select(Candidate).where(func.lower(Candidate.email) == norm_email))
            if not cand:
                cand = Candidate(
                    name=form.name.data,
                    email=norm_email,
                    phone=(form.phone.data or "").strip(),
                )
                s.add(cand)
                try:
                    s.flush()
                except IntegrityError:
                    s.rollback()
                    cand = s.scalar(select(Candidate).where(func.lower(Candidate.email) == norm_email))
                    if not cand:
                        flash("We couldn't process your details. Please try again.", "danger")
                        return render_template("apply.html", form=form, job=job)

            # 2) Reject duplicate application for same job
            existing_app = s.scalar(
                select(Application).where(Application.job_id == job.id, Application.candidate_id == cand.id)
            )
            if existing_app:
                flash("You’ve already applied for this role. We’ve kept your original application.", "info")
                return redirect(url_for("public_job", token=token))

            # 3) Require CV
            cv_file = request.files.get("cv")
            if not cv_file or not cv_file.filename:
                flash("Please upload a CV", "danger")
                return render_template("apply.html", form=form, job=job)

            # 4) Save CV to static/uploads/cvs and store the basename
            try:
                stored_basename = save_cv(cv_file)              # ← basename only
                original_name   = cv_file.filename or stored_basename
            except Exception as e:
                flash(f"Upload failed: {e}", "danger")
                return render_template("apply.html", form=form, job=job)

            # 5) Create Document row (basename only in filename)
            doc = Document(
                candidate_id=cand.id,
                doc_type="cv",
                filename=stored_basename,
                original_name=original_name,
            )
            s.add(doc)
            s.flush()

            # 6) Create application
            appn = Application(
                job_id=job.id,
                candidate_id=cand.id,
                cover_note=form.cover_note.data or "",
            )
            s.add(appn)
            s.commit()

            # 7) (Optional) kick off async enrichment if you have it
            try:
                executor.submit(_async_enrich, appn.id)
            except Exception:
                current_app.logger.warning("Async enrich submit failed", exc_info=True)

            flash("Application submitted. We’re processing your CV & AI insights now.", "success")
            return redirect(url_for("public_job", token=token))

    return render_template("apply.html", form=form, job=job)

@app.route("/my/timesheets", methods=["GET", "POST"])
@worker_required
def my_timesheets():
    """
    Minimal worker portal to submit a weekly timesheet.
    Reuses your existing Timesheet model.
    """
    now = datetime.datetime.utcnow()
    start = (now - datetime.timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + datetime.timedelta(days=7)

    # Single engagement picker for simplicity
    class _TSForm(FlaskForm):
        engagement_id = SelectField("Engagement", coerce=int, validators=[DataRequired()])
        hours = IntegerField("Hours", validators=[DataRequired()])
        notes = TextAreaField("Notes", validators=[WTOptional()])
        submit = SubmitField("Submit")

    with Session(engine) as s:
        engagements = s.scalars(select(Engagement).order_by(Engagement.name.asc())).all()
        choices = [(e.id, f"{e.name} ({e.client or '—'})") for e in engagements]

    form = _TSForm()
    form.engagement_id.choices = choices

    if form.validate_on_submit():
        with Session(engine) as s:
            ts = Timesheet(
                user_id=int(current_user.id),
                engagement_id=form.engagement_id.data,
                period_start=start,
                period_end=end,
                hours=int(form.hours.data or 0),
                notes=form.notes.data or "",
                status="Submitted",
                submitted_at=datetime.datetime.utcnow(),
            )
            s.add(ts)
            s.commit()
        flash("Timesheet submitted.", "success")
        return redirect(url_for("my_timesheets"))

    # List recent timesheets for the logged-in user
    with Session(engine) as s:
        mine = s.execute(
            select(Timesheet, Engagement)
            .join(Engagement, Engagement.id == Timesheet.engagement_id)
            .where(Timesheet.user_id == int(current_user.id))
            .order_by(Timesheet.period_start.desc())
            .limit(20)
        ).all()

    return render_template("timesheets_portal.html", form=form, items=mine, week=(start, end))

@app.route("/action/candidate/regenerate_summary", methods=["POST"])
def candidate_regenerate_summary():
    """
    Rebuild AI summary from the latest CV, (re)tag the candidate, mirror tag names into
    Candidate.skills, and (optionally) compute/update an AI match score against a job.

    Notes:
      - Does NOT create Shortlist entries.
      - Uses _pick_ai_score(payload) to normalise score keys.
      - Tries both doc-object and filepath signatures for extract_cv_text().
    """
    # ---- Inputs
    try:
        cand_id = int(request.form.get("candidate_id") or 0)
    except Exception:
        cand_id = 0
    job_id = request.form.get("job_id")
    try:
        job_id = int(job_id) if job_id else None
    except Exception:
        job_id = None

    if not cand_id:
        flash("Missing candidate id.", "warning")
        return redirect(request.referrer or url_for("resource_pool"))

    # ---- Lazy imports to avoid circulars
    from sqlalchemy import select
    from sqlalchemy.orm import Session as SASession

    try:
        # models + engine from your app
        from app import (
            engine, Candidate, Application, Document, Job,
            TaxonomyTag, CandidateTag
        )
    except Exception:
        flash("Server configuration error.", "danger")
        return redirect(request.referrer or url_for("resource_pool"))

    # Optional AI utilities
    try:
        from app import extract_cv_text
    except Exception:
        extract_cv_text = None  # type: ignore
    try:
        from app import ai_summarise
    except Exception:
        ai_summarise = None  # type: ignore
    try:
        from app import ai_score_with_explanation
    except Exception:
        ai_score_with_explanation = None  # type: ignore

    # ---- Helpers -------------------------------------------------------------
    def _doc_abs_path(doc) -> str:
        """Resolve absolute path for a Document row (fallback to /static)."""
        try:
            from app import _doc_file_path  # type: ignore
            return _doc_file_path(doc)
        except Exception:
            root = current_app.root_path
            rel = getattr(doc, "filename", "") or ""
            return os.path.join(root, "static", rel)

    def _safe_extract_text(file_path: str, original_name: str) -> str:
        """Lightweight extractor when extract_cv_text isn't available."""
        name = (original_name or file_path or "").lower()
        # PDF
        if name.endswith(".pdf"):
            try:
                import pdfplumber
                with pdfplumber.open(file_path) as pdf:
                    bits = [(p.extract_text() or "") for p in pdf.pages]
                txt = "\n".join(bits).strip()
                if txt:
                    return txt
            except Exception:
                pass
        # DOCX
        if name.endswith(".docx"):
            try:
                import docx
                d = docx.Document(file_path)
                txt = "\n".join([p.text for p in d.paragraphs]).strip()
                if txt:
                    return txt
            except Exception:
                pass
        # Plain text fallback
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read().strip()
        except Exception:
            return ""

def _job_text(job) -> str:
    for attr in ("description", "desc", "requirements", "summary", "details", "spec"):
        if hasattr(job, attr):
            v = getattr(job, attr) or ""
            v = v.strip()
            if v:
                return v
    return (getattr(job, "title", "") or "").strip()

    # ---- Main ---------------------------------------------------------------
    with SASession(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            flash("Candidate not found.", "warning")
            return redirect(url_for("resource_pool"))

        # Latest CV (prefer uploaded_at if present)
        order_col = getattr(Document, "uploaded_at", Document.id)
        doc = s.execute(
            select(Document)
            .where(Document.candidate_id == cand_id)
            .where(getattr(Document, "doc_type", Document.doc_type) == "cv")
            .order_by(order_col.desc())
            .limit(1)
        ).scalar_one_or_none()
        if not doc:
            flash("No CV found for this candidate.", "warning")
            return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=job_id))

        # Extract text from CV — try app's extractor then safe fallbacks
        cv_text = ""
        try:
            if extract_cv_text and callable(extract_cv_text):
                try:
                    # Some versions accept a Document, others a file path
                    cv_text = extract_cv_text(doc) or ""
                except TypeError:
                    cv_text = extract_cv_text(_doc_abs_path(doc)) or ""
            else:
                cv_text = _safe_extract_text(_doc_abs_path(doc), getattr(doc, "original_name", "") or doc.filename)
        except Exception:
            cv_text = ""

        # Build summary with guardrails
        summary = ""
        try:
            if ai_summarise and callable(ai_summarise):
                summary = ai_summarise(cv_text or "") or ""
        except Exception as e:
            current_app.logger.exception("ai_summarise failed: %s", e)

        # Persist summary on latest application (and mirror to Candidate.ai_summary)
        latest_app = s.execute(
            select(Application)
            .where(Application.candidate_id == cand_id)
            .order_by(Application.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if latest_app and hasattr(latest_app, "ai_summary"):
            latest_app.ai_summary = summary
        if hasattr(cand, "ai_summary"):
            cand.ai_summary = summary

        # TAGS: single source of truth via TaxonomyTag table
        text_lc = (cv_text or "").lower()
        matched_ids = set()
        all_tags = s.execute(select(TaxonomyTag)).scalars().all()
        for tg in all_tags:
            token = (tg.tag or "").strip()
            if token and token.lower() in text_lc:
                matched_ids.add(tg.id)

        if matched_ids:
            existing_ids = {
                tid for (tid,) in s.execute(
                    select(CandidateTag.tag_id).where(CandidateTag.candidate_id == cand.id)
                ).all()
            }
            for tid in matched_ids:
                if tid not in existing_ids:
                    s.add(CandidateTag(candidate_id=cand.id, tag_id=tid))

            # Mirror tags into Candidate.skills (readable comma list; preserve order/uniq)
            tag_rows = s.execute(
                select(TaxonomyTag)
                .join(CandidateTag, CandidateTag.tag_id == TaxonomyTag.id)
                .where(CandidateTag.candidate_id == cand.id)
                .order_by(TaxonomyTag.tag.asc())
            ).scalars().all()
            tag_names = [t.tag for t in tag_rows if (t.tag or "").strip()]
            cand.skills = ", ".join(dict.fromkeys(tag_names))

        # Optional scoring (no shortlist side-effects)
        target_job = None
        if job_id:
            target_job = s.get(Job, job_id)
        elif latest_app:
            target_job = s.get(Job, getattr(latest_app, "job_id", None))

        if target_job and cv_text.strip() and ai_score_with_explanation:
            try:
                payload = ai_score_with_explanation(_job_text(target_job), cv_text) or {}
                score = _pick_ai_score(payload)  # <-- normalises 'final'/'blended_score'/etc.
                if latest_app is not None and hasattr(latest_app, "ai_score"):
                    latest_app.ai_score = score
                if hasattr(cand, "ai_score"):
                    cand.ai_score = score
                if latest_app is not None and hasattr(latest_app, "ai_explanation"):
                    latest_app.ai_explanation = (payload.get("explanation") or "")[:7999]
            except Exception as e:
                current_app.logger.exception("ai_score_with_explanation failed: %s", e)

        s.commit()

    flash("AI summary regenerated and tags/score updated.", "success")
    return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=job_id))

@app.route("/action/candidate/delete", methods=["POST"])
def candidate_delete_action():
    cand_id = int((request.form.get("candidate_id") or "0") or 0)
    confirm = (request.form.get("confirm") or "").lower() == "yes"
    if not cand_id:
        flash("Missing candidate id.", "warning")
        return redirect(request.referrer or url_for("resource_pool"))
    if not confirm:
        flash("Deletion cancelled.", "info")
        return redirect(request.referrer or url_for("resource_pool"))

    with Session(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            flash("Candidate not found.", "warning")
            return redirect(request.referrer or url_for("resource_pool"))

        app_ids = [aid for (aid,) in s.execute(
            select(Application.id).where(Application.candidate_id == cand_id)
        ).all()]

        if app_ids:
            s.execute(delete(ESigRequest).where(ESigRequest.application_id.in_(app_ids)))
            s.execute(delete(TrustIDCheck).where(TrustIDCheck.application_id.in_(app_ids)))
            s.execute(delete(Application).where(Application.id.in_(app_ids)))

        s.execute(delete(Shortlist).where(Shortlist.candidate_id == cand_id))
        s.execute(delete(CandidateTag).where(CandidateTag.candidate_id == cand_id))
        s.delete(cand)
        s.commit()

    flash("Candidate deleted.", "success")
    return redirect(request.referrer or url_for("resource_pool"))

@app.route("/application/<int:app_id>", methods=["GET","POST"])
def application_detail(app_id):
    interview_form = InterviewForm()

    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id == app_id))
        if not appn:
            abort(404)

        cand = s.get(Candidate, appn.candidate_id)
        job  = s.get(Job, appn.job_id)
        if not cand or not job:
            abort(404)

        # Engagement context (may be None if data is inconsistent)
        engagement = s.get(Engagement, job.engagement_id) if job.engagement_id else None
        eng_status = ((engagement.status if engagement else "") or "").strip().lower()
        eng_active = eng_status in {"active", "in-flight", "in progress"}

        docs = s.scalars(select(Document).where(Document.candidate_id == cand.id)).all()

        # TrustID (may be None) + safe parsed result
        trust = s.scalar(select(TrustIDCheck).where(TrustIDCheck.application_id == appn.id))
        trust_result = None
        if trust and getattr(trust, "result_json", None):
            try:
                trust_result = json.loads(trust.result_json)
            except Exception:
                txt = trust.result_json or ""
                trust_result = {"raw": (txt[:400] + "…") if len(txt) > 400 else txt}

        # E-sign (fetch inside the session)
        esig = s.scalar(select(ESigRequest).where(ESigRequest.application_id == appn.id))

        # Candidate's current tags (for sidebar)
        cand_tags = s.scalars(
            select(TaxonomyTag)
            .join(CandidateTag, CandidateTag.tag_id == TaxonomyTag.id)
            .where(CandidateTag.candidate_id == cand.id)
            .order_by(TaxonomyTag.tag.asc())
        ).all()

        # All tags grouped by category for the dropdown
        cats = s.scalars(
            select(TaxonomyCategory).order_by(TaxonomyCategory.type.asc(), TaxonomyCategory.name.asc())
        ).all()
        tags_by_cat = {
            c.id: s.scalars(
                select(TaxonomyTag).where(TaxonomyTag.category_id == c.id).order_by(TaxonomyTag.tag.asc())
            ).all()
            for c in cats
        }

        # Use the global helper so Withdrawn/Closed are treated as not open
        job_open = _job_is_open(job)
        applied_on = appn.created_at

        # Stage banner context (very light-touch ordering)
        # (contract signed > contract issued > vetting > interview completed > interview scheduled > shortlisted > declared)
        stage_ctx = None
        if esig and (esig.status or "").lower() in {"signed", "completed"}:
            stage_ctx = f"Contract signed for {job.title}"
        elif esig and (esig.status or "").lower() in {"sent", "delivered"}:
            stage_ctx = f"Contract issued for {job.title}"
        elif trust and (trust.status or "").lower() in {"created", "inprogress"}:
            stage_ctx = "Vetting in progress"
        elif appn.interview_completed_at:
            stage_ctx = "Interview completed"
        elif appn.interview_scheduled_at:
            when = appn.interview_scheduled_at.strftime("%Y-%m-%d %H:%M")
            stage_ctx = f"Interview scheduled — {when}"
        else:
            # shortlisted?
            sl_exists = s.scalar(
                select(Shortlist.id).where(Shortlist.job_id == job.id, Shortlist.candidate_id == cand.id).limit(1)
            )
            if sl_exists:
                stage_ctx = f"Shortlisted for {job.title}"
            else:
                stage_ctx = "Declared interest"

        # Disable action buttons if engagement not active or job not open
        actions_disabled = (not eng_active) or (not job_open)

    # Render (note: no DB work after the session closes)
    return render_template(
        "application_detail.html",
        appn=appn,
        cand=cand,
        job=job,
        engagement=engagement,
        docs=docs,
        trust=trust,
        trust_result=trust_result,
        esig=esig,
        interview_form=interview_form,
        # Tags-only context:
        cand_tags=cand_tags,
        cats=cats,
        tags_by_cat=tags_by_cat,
        # Meta:
        job_open=job_open,
        applied_on=applied_on,
        # Stage banner + UX hints:
        stage_context=stage_ctx,
        actions_disabled=actions_disabled,
    )

@app.route("/action/score/app/<int:app_id>", methods=["POST"], endpoint="action_score_by_app")
def action_score_by_app(app_id):
    from sqlalchemy import select
    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id == app_id))
        if not appn:
            abort(404)

        job = s.get(Job, appn.job_id)
        if not job:
            abort(404)

        # latest CV
        order_col = getattr(Document, "uploaded_at", Document.id)
        doc = s.execute(
            select(Document)
            .where(Document.candidate_id == appn.candidate_id, getattr(Document, "doc_type", Document.doc_type) == "cv")
            .order_by(order_col.desc())
            .limit(1)
        ).scalar_one_or_none()

        cv_text = ""
        if doc:
            try:
                cv_text = extract_cv_text(doc) or ""
            except TypeError:
                try:
                    from app import _doc_file_path
                    cv_text = extract_cv_text(_doc_file_path(doc)) or ""
                except Exception:
                    cv_text = ""
            except Exception:
                cv_text = ""

        if not cv_text.strip():
            flash("No readable CV found to score.", "warning")
            return redirect(url_for("application_detail", app_id=app_id))

        payload = {}
        try:
            payload = ai_score_with_explanation(job.description or "", cv_text) or {}
        except Exception as e:
            current_app.logger.exception("ai_score_with_explanation failed: %s", e)
            flash("AI scoring failed.", "danger")
            return redirect(url_for("application_detail", app_id=app_id))

        appn.ai_score = _pick_ai_score(payload)
        appn.ai_explanation = (payload.get("explanation") or "")[:7999]
        s.commit()

    flash("AI score updated", "success")
    return redirect(url_for("application_detail", app_id=app_id))

@app.route("/action/summarise/<int:app_id>", methods=["POST"])
def action_summarise(app_id):
    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id==app_id))
        if not appn:
            abort(404)
        doc = s.scalar(
            select(Document)
            .where(Document.candidate_id==appn.candidate_id)
            .order_by(Document.uploaded_at.desc())
        )
        cv_text = extract_cv_text(doc) if doc else ""
        appn.ai_summary = ai_summarise(cv_text or "")
        s.commit()
    flash("AI summary generated", "success")
    return redirect(url_for("application_detail", app_id=app_id))

# -------- TrustID placeholders (as before) --------
def trustid_headers():
    return {"Authorization": f"Bearer {TRUSTID_API_KEY}", "Content-Type": "application/json"}

@app.route("/action/trustid/<int:app_id>", methods=["POST"])
def action_trustid(app_id):
    do_rtw = bool(request.form.get("rtw"))
    do_idv = bool(request.form.get("idv", True))
    do_dbs = bool(request.form.get("dbs"))
    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id==app_id))
        cand = s.scalar(select(Candidate).where(Candidate.id==appn.candidate_id))

        payload = {
            "external_ref": f"APP-{appn.id}",
            "candidate": {"name": cand.name, "email": cand.email},
            "checks": {"rtw": do_rtw, "idv": do_idv, "dbs": do_dbs},
            "webhooks": {"result": f"{APP_BASE_URL}/webhook/trustid"}
        }
        try:
            resp = requests.post(f"{TRUSTID_BASE_URL}/apps", headers=trustid_headers(), data=json.dumps(payload), timeout=15)
            if resp.status_code >= 300:
                raise RuntimeError(f"TrustID error: {resp.status_code} {resp.text}")
            data = resp.json()
            trust_app_id = data.get("id", "")
        except Exception as e:
            flash(f"TrustID create failed: {e}", "danger")
            return redirect(url_for("application_detail", app_id=app_id))

        tic = TrustIDCheck(application_id=appn.id, rtw=do_rtw, idv=do_idv, dbs=do_dbs,
                           trustid_application_id=trust_app_id, status="InProgress")
        s.add(tic)
        s.commit()
    flash("TrustID checks initiated", "success")
    return redirect(url_for("application_detail", app_id=app_id))

@app.route("/webhook/trustid", methods=["POST"])
def webhook_trustid():
    """
    Receives TrustID webhook notifications, verifies signature (if secret configured),
    stores the raw event, and updates TrustIDCheck records with the latest result JSON.
    """

    # --- Verify HMAC signature if configured ---
    payload_bytes = request.get_data()
    event_type = request.headers.get("X-TrustID-Event", "unknown")
    received_sig = request.headers.get("X-TrustID-Signature", "")

    if TRUSTID_WEBHOOK_SECRET:
        try:
            expected_sig = hmac.new(
                TRUSTID_WEBHOOK_SECRET.encode("utf-8"),
                payload_bytes,
                hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected_sig, received_sig):
                current_app.logger.warning("⚠️ TrustID webhook signature verification failed")
                abort(401)
        except Exception as e:
            current_app.logger.warning(f"⚠️ TrustID webhook signature error: {e}")
            abort(401)

    # --- Log the event payload for audit trail ---
    payload_text = payload_bytes.decode("utf-8", errors="ignore")
    with Session(engine) as s:
        s.add(WebhookEvent(
            source="trustid",
            event_type=event_type,
            payload=payload_text[:39999]
        ))
        s.commit()

    # --- Parse event JSON ---
    data = {}
    try:
        data = json.loads(payload_text)
    except Exception:
        pass

    trustid_app_id = data.get("application_id") or data.get("id") or ""
    if not trustid_app_id:
        current_app.logger.warning("⚠️ No TrustID application_id found in webhook payload")
        return jsonify({"ok": False, "error": "missing application_id"}), 400

    # --- Fetch latest TrustID result from API ---
    try:
        resp = requests.get(
            f"{TRUSTID_BASE_URL}/apps/{trustid_app_id}/results",
            headers={"Authorization": f"Bearer {TRUSTID_API_KEY}", "Content-Type": "application/json"},
            timeout=15,
        )
        if resp.status_code >= 300:
            raise RuntimeError(f"TrustID API returned {resp.status_code}: {resp.text}")
        result_json = resp.json()
        status = "Completed"
    except Exception as e:
        result_json = {"error": str(e)}
        status = "Error"
        current_app.logger.warning(f"⚠️ TrustID webhook result fetch failed for {trustid_app_id}: {e}")

    # --- Update our local TrustIDCheck record ---
    with Session(engine) as s:
        tic = s.scalar(select(TrustIDCheck).where(TrustIDCheck.trustid_application_id == trustid_app_id))
        if tic:
            tic.result_json = json.dumps(result_json)[:19999]
            tic.status = status
            s.commit()
        else:
            current_app.logger.warning(f"⚠️ No TrustIDCheck row found for {trustid_app_id}")

    return jsonify({"ok": True})

# -------- Interview scheduling (ICS) --------
@app.route("/action/schedule_interview/<int:app_id>", methods=["POST"])
def action_schedule_interview(app_id):
    form_dt = request.form.get("scheduled_at")
    interviewer_email = request.form.get("interviewer_email") or INTERVIEWER_EMAIL

    # parse start time
    start = dtparser.parse(form_dt) if form_dt else None
    if not start:
        flash("Please provide a valid date/time", "danger")
        return redirect(url_for("application_detail", app_id=app_id))
    end = start + datetime.timedelta(hours=1)

    # we'll fill these before session closes
    cand_name = ""
    cand_email = ""
    job_title = ""

    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id == app_id))
        if not appn:
            abort(404)

        cand = s.scalar(select(Candidate).where(Candidate.id == appn.candidate_id))
        job  = s.scalar(select(Job).where(Job.id == appn.job_id))

        if not cand or not job:
            abort(404)

        # cache the bits we need OUTSIDE the session
        cand_name = cand.name or ""
        cand_email = cand.email or ""
        job_title = job.title or ""

        # update DB
        appn.interview_scheduled_at = start
        appn.status = "Interview"
        s.commit()

    # now we're OUTSIDE the session but we only use plain strings, not ORM objects
    summary = f"Interview — {job_title}"
    description = f"Interview for {job_title} with {cand_name}"
    location = "Microsoft Teams / Zoom (link to follow)"

    ics_bytes = ics_invite(
        summary,
        description,
        start,
        end,
        location,
        SMTP_FROM,
        cand_email,
    )

    # send calendar invite to candidate
    send_email(
        cand_email,
        summary,
        f"<p>Hi {cand_name}, your interview is scheduled for {start}.</p>",
        attachments=[("interview.ics", ics_bytes, "text/calendar")],
    )

    # send calendar invite to interviewer
    send_email(
        interviewer_email,
        summary,
        f"<p>Interview scheduled with {cand_name} for {start}.</p>",
        attachments=[("interview.ics", ics_bytes, "text/calendar")],
    )

    flash("Interview scheduled and invites sent", "success")
    return redirect(url_for("application_detail", app_id=app_id))

@app.route("/action/mark_interview_completed/<int:app_id>", methods=["POST"])
def action_mark_interview_completed(app_id):
    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id==app_id))
        if not appn:
            abort(404)
        appn.interview_completed_at = datetime.datetime.utcnow()
        s.commit()
    flash("Interview marked as completed", "success")
    return redirect(url_for("application_detail", app_id=app_id))

@app.route("/action/complete_interview/<int:app_id>", methods=["POST"])
def action_complete_interview(app_id):
    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id == app_id))
        if not appn:
            abort(404)
        appn.status = "Interview Completed"
        appn.interview_completed_at = datetime.datetime.utcnow()
        s.commit()
    flash("Interview marked as completed.", "success")
    return redirect(url_for("application_detail", app_id=app_id))

@app.route("/action/save_interview_notes/<int:app_id>", methods=["POST"])
def action_save_interview_notes(app_id):
    notes = request.form.get("interview_notes", "").strip()
    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id == app_id))
        if not appn:
            abort(404)
        appn.interview_notes = notes
        s.commit()
    flash("Interview notes saved.", "success")
    return redirect(url_for("application_detail", app_id=app_id))

# -------- E-signature: send & poll --------
def send_esign_dropbox_sign(appn_id: int, signer_name: str, signer_email: str, subject: str, message: str):
    if not HELLOSIGN_API_KEY or ApiClient is None:
        raise RuntimeError("Dropbox Sign SDK or API key not configured")
    conf = Configuration(username=HELLOSIGN_API_KEY)
    with ApiClient(conf) as api_client:
        sig_api = SignatureRequestApi(api_client)
        signers = [SubSignatureRequestSigner(email_address=signer_email, name=signer_name)]
        data = SignatureRequestSendRequest(
            title=subject,
            subject=subject,
            message=message,
            signers=signers,
            files=[],
            test_mode=True
        )
        res = sig_api.signature_request_send(data)
        return res.signature_request.signature_request_id

def poll_esign_dropbox_sign(request_id: str):
    if not HELLOSIGN_API_KEY or ApiClient is None:
        raise RuntimeError("Dropbox Sign SDK or API key not configured")
    conf = Configuration(username=HELLOSIGN_API_KEY)
    with ApiClient(conf) as api_client:
        sig_api = SignatureRequestApi(api_client)
        res = sig_api.signature_request_get(request_id)
        status = "Sent"
        if res and res.signature_request and res.signature_request.is_complete:
            status = "Signed"
        return status

def send_esign_docusign(appn_id: int, signer_name: str, signer_email: str, subject: str, message: str):
    if dse is None or not DOCUSIGN_ACCESS_TOKEN or not DOCUSIGN_ACCOUNT_ID:
        raise RuntimeError("DocuSign SDK or access token/account not configured")
    api_client = dse.ApiClient()
    api_client.host = DOCUSIGN_BASE_PATH
    api_client.set_default_header("Authorization", f"Bearer {DOCUSIGN_ACCESS_TOKEN}")
    envelopes_api = dse.EnvelopesApi(api_client)
    doc_base64 = base64.b64encode(b"Please sign this simple agreement.").decode("ascii")
    document = dse.Document(document_base64=doc_base64, name="Agreement", file_extension="txt", document_id="1")
    signer = dse.Signer(email=signer_email, name=signer_name, recipient_id="1", routing_order="1")
    sign_here = dse.SignHere(document_id="1", page_number="1", recipient_id="1", tab_label="SignHere", x_position="75", y_position="572")
    tabs = dse.Tabs(sign_here_tabs=[sign_here])
    signer.tabs = tabs
    recipients = dse.Recipients(signers=[signer])
    envelope_definition = dse.EnvelopeDefinition(email_subject=subject, documents=[document], recipients=recipients, status="sent")
    results = envelopes_api.create_envelope(account_id=DOCUSIGN_ACCOUNT_ID, envelope_definition=envelope_definition)
    return results.envelope_id

def poll_esign_docusign(request_id: str):
    if dse is None or not DOCUSIGN_ACCESS_TOKEN or not DOCUSIGN_ACCOUNT_ID:
        raise RuntimeError("DocuSign SDK or access token/account not configured")
    api_client = dse.ApiClient()
    api_client.host = DOCUSIGN_BASE_PATH
    api_client.set_default_header("Authorization", f"Bearer {DOCUSIGN_ACCESS_TOKEN}")
    envelopes_api = dse.EnvelopesApi(api_client)
    res = envelopes_api.get_envelope(account_id=DOCUSIGN_ACCOUNT_ID, envelope_id=request_id)
    status_map = {"sent":"Sent","completed":"Signed","declined":"Declined","voided":"Error"}
    return status_map.get((res.status or "").lower(), res.status or "Unknown")

@app.route("/action/esign/<int:app_id>", methods=["POST"])
def action_esign(app_id):
    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id==app_id))
        cand = s.scalar(select(Candidate).where(Candidate.id==appn.candidate_id))
        job = s.scalar(select(Job).where(Job.id==appn.job_id))

        subject = f"Contract — {job.title}"
        message = "Please review and sign your contract."
        try:
            if ESIGN_PROVIDER == "dropbox_sign":
                req_id = send_esign_dropbox_sign(appn.id, cand.name, cand.email, subject, message)
            elif ESIGN_PROVIDER == "docusign":
                req_id = send_esign_docusign(appn.id, cand.name, cand.email, subject, message)
            else:
                raise RuntimeError("Unsupported ESIGN_PROVIDER")
        except Exception as e:
            flash(f"E-sign send failed: {e}", "danger")
            return redirect(url_for("application_detail", app_id=app_id))

        es = s.scalar(select(ESigRequest).where(ESigRequest.application_id==appn.id))
        if not es:
            es = ESigRequest(application_id=appn.id, provider=ESIGN_PROVIDER, request_id=req_id, status="Sent", sent_at=datetime.datetime.utcnow())
            s.add(es)
        else:
            es.request_id = req_id
            es.provider = ESIGN_PROVIDER
            es.status = "Sent"
            es.sent_at = datetime.datetime.utcnow()
        s.commit()
    flash("Contract sent for e-signature", "success")
    return redirect(url_for("application_detail", app_id=app_id))

@app.route("/action/esign_status/<int:app_id>", methods=["POST"])
def action_esign_status(app_id):
    with Session(engine) as s:
        es = s.scalar(select(ESigRequest).where(ESigRequest.application_id==app_id))
        if not es:
            flash("No e-sign request found", "warning")
            return redirect(url_for("application_detail", app_id=app_id))
        try:
            if es.provider == "dropbox_sign":
                status = poll_esign_dropbox_sign(es.request_id)
            elif es.provider == "docusign":
                status = poll_esign_docusign(es.request_id)
            else:
                status = "Unknown"
        except Exception as e:
            flash(f"E-sign status failed: {e}", "danger")
            return redirect(url_for("application_detail", app_id=app_id))

        es.status = status
        if status == "Signed":
            es.signed_at = datetime.datetime.utcnow()
        s.commit()
    flash(f"E-sign status: {status}", "info")
    return redirect(url_for("application_detail", app_id=app_id))

@app.route("/webhook/esign", methods=["POST"])
def webhook_esign():
    payload = request.json or {}
    with Session(engine) as s:
        s.add(WebhookEvent(source="esign", event_type=str(payload.get('event','unknown')), payload=json.dumps(payload)[:39999]))
        s.commit()
    return jsonify({"ok": True})

# ---- Request updated CV ----
@app.route("/action/request_updated_cv/<int:app_id>", methods=["POST"])
def action_request_updated_cv(app_id):
    with Session(engine) as s:
        appn = s.scalar(select(Application).where(Application.id==app_id))
        cand = s.scalar(select(Candidate).where(Candidate.id==appn.candidate_id))
        link = f"{APP_BASE_URL}/candidate/{cand.id}/upload_cv"
        html = f"""
        <h3>Request for updated CV</h3>
        <p>Hi {cand.name}, we enjoyed working with you. Please upload an updated CV here:</p>
        <p><a href="{link}">{link}</a></p>
        """
        send_email(cand.email, "Please upload an updated CV", html)
    flash("CV update request sent", "success")
    return redirect(url_for("application_detail", app_id=app_id))

@app.route("/candidate/<int:cand_id>")
def candidate_profile(cand_id: int):
    # Optional context passed when arriving from engagement lists
    stage = (request.args.get("stage") or "").strip().lower()
    ctx = {
        "stage": stage or None,
        "job_id": request.args.get("job_id"),
        "job_title": request.args.get("job_title"),
        "interview_at": request.args.get("interview_at"),
    }

    with Session(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            abort(404)

        latest_app = s.scalar(
            select(Application)
            .where(Application.candidate_id == cand_id)
            .order_by(Application.created_at.desc())
        )

        job = None
        job_open = False
        applied_on = None
        docs = s.scalars(select(Document).where(Document.candidate_id == cand.id)).all()

        if latest_app:
            job = s.scalar(select(Job).where(Job.id == latest_app.job_id))
            job_open = _job_is_open(job)
            applied_on = latest_app.created_at

        # Tags data for the sidebar card
        cand_tags = s.scalars(
            select(TaxonomyTag)
            .join(CandidateTag, CandidateTag.tag_id == TaxonomyTag.id)
            .where(CandidateTag.candidate_id == cand.id)
            .order_by(TaxonomyTag.tag.asc())
        ).all()

        cats = s.scalars(
            select(TaxonomyCategory).order_by(TaxonomyCategory.type.asc(), TaxonomyCategory.name.asc())
        ).all()

        tags_by_cat = {
            c.id: s.scalars(
                select(TaxonomyTag).where(TaxonomyTag.category_id == c.id).order_by(TaxonomyTag.tag.asc())
            ).all()
            for c in cats
        }

    return render_template(
        "application_detail.html",
        appn=latest_app,            # can be None
        cand=cand,
        job=job,
        docs=docs,
        trust=None,
        esig=None,
        interview_form=None,
        job_open=job_open,
        applied_on=applied_on,
        from_candidate=True,

        # taxonomy/tag data
        cand_tags=cand_tags,
        cats=cats,
        tags_by_cat=tags_by_cat,

        # engagement/list context for banner in template
        context=ctx if ctx.get("stage") else None,
    )

# -------- Engagement Dashboard --------
@app.route("/engagement/<int:eng_id>/dashboard")
def engagement_dashboard(eng_id):
    UNASSIGNED = "Unassigned"

    with Session(engine) as s:
        engagement = s.scalar(select(Engagement).where(Engagement.id == eng_id))
        if not engagement:
            abort(404)

        eng_status = (getattr(engagement, "status", "") or "").strip().lower()
        is_eng_active = eng_status in {"active", "in-flight", "in progress"}

        # --- Plan (per role) ---
        plans = s.execute(
            select(EngagementPlan.role_type, EngagementPlan.planned_count)
            .where(EngagementPlan.engagement_id == eng_id)
        ).all()
        planned_by_role = {r: 0 for r in ROLE_TYPES}
        for r, cnt in plans:
            if r in planned_by_role:
                planned_by_role[r] = int(cnt or 0)
        total_planned = sum(planned_by_role.values())

        # If engagement finished -> skip activity logic
        if not is_eng_active:
            display_roles = [r for r, v in planned_by_role.items() if v > 0] or [UNASSIGNED]
            role_metrics = {
                r: {
                    "planned": planned_by_role.get(r, 0),
                    "declared": 0, "sched": 0, "done": 0,
                    "vetting": 0, "issued": 0, "signed": 0
                }
                for r in display_roles
            }
            totals_row = {
                "planned": total_planned, "declared": 0, "sched": 0, "done": 0,
                "vetting": 0, "issued": 0, "signed": 0
            }
            return render_template(
                "engagement_dashboard.html",
                engagement=engagement,
                planned_by_role=planned_by_role,
                declared_rows=[], interview_sched=[], interview_done=[],
                vetting=[], contract_issued=[], contract_signed=[],
                total_planned=total_planned, total_signed=0, progress_pct=0,
                ROLE_TYPES=ROLE_TYPES, display_roles=display_roles,
                role_metrics=role_metrics, totals_row=totals_row,
                shortlist_count=0, shortlisted=[], jobs_active=[],
                job_declared={}, job_shortlisted={}, engagement_finished=True,
                tile_shortlist=0, tile_interview_sched=0, tile_interview_done=0,
                tile_vetting=0, tile_contract_issued=0, tile_contract_signed=0,
            )

        # ---------- ACTIVE engagement logic ----------

        # Core query for open jobs only
        sl_exists = exists(
            select(Shortlist.id).where(
                Shortlist.job_id == Application.job_id,
                Shortlist.candidate_id == Application.candidate_id,
            )
        )

        declared_q = (
            select(Application, Candidate, Job)
            .join(Candidate, Candidate.id == Application.candidate_id)
            .join(Job, Job.id == Application.job_id)
            .where(
                Job.engagement_id == eng_id,
                Job.status == "Open",
                ~sl_exists,
            )
            .order_by(Application.created_at.desc())
        )
        declared = s.execute(declared_q).all()

        def to_row(tup):
            a, c, j = tup
            return {
                "app_id": a.id,
                "status": a.status,
                "ai_score": a.ai_score,
                "interview_at": a.interview_scheduled_at,
                "interview_done_at": a.interview_completed_at,
                "candidate": {"id": c.id, "name": c.name, "email": c.email},
                "job": {"id": j.id, "title": j.title, "role_type": j.role_type or ""},
            }

        declared_rows = [to_row(t) for t in declared]

        # --- interview buckets (pending-review only, for the side panels if needed) ---
        interview_sched = [
            r for r in declared_rows
            if r["interview_at"] is not None and r["interview_done_at"] is None
        ]
        interview_done = [
            r for r in declared_rows
            if r["interview_done_at"] is not None
        ]

        # --- shortlist (only open jobs) ---
        shortlist_rows_all = s.execute(
            select(Shortlist, Candidate, Job)
            .join(Job, Job.id == Shortlist.job_id)
            .join(Candidate, Candidate.id == Shortlist.candidate_id)
            .where(Job.engagement_id == eng_id, Job.status == "Open")
            .order_by(Shortlist.created_at.desc())
        ).all()

        shortlisted = []
        for sl, c, j in shortlist_rows_all:
            app_obj = s.scalar(
                select(Application)
                .where(Application.candidate_id == c.id, Application.job_id == j.id)
                .order_by(Application.created_at.desc())
            )
            if app_obj and (
                app_obj.interview_scheduled_at is not None
                or app_obj.interview_completed_at is not None
            ):
                continue
            shortlisted.append({
                "shortlist_id": sl.id,
                "created_at": sl.created_at,
                "candidate_id": c.id,
                "candidate": {"id": c.id, "name": c.name, "email": c.email},
                "job": {"id": j.id, "title": j.title},
            })
        shortlist_count = len(shortlisted)

        # === KPI TILE NUMBERS (use ALL apps in the engagement) ===
        apps_all = s.execute(
            select(
                Application.id, Application.candidate_id, Application.job_id,
                Application.interview_scheduled_at, Application.interview_completed_at,
                Job.role_type
            )
            .join(Job, Job.id == Application.job_id)
            .where(Job.engagement_id == eng_id, Job.status == "Open")
        ).all()

        sched_set, done_set, vetting_set, issued_set, signed_set = set(), set(), set(), set(), set()
        app_id_list = [a[0] for a in apps_all]

        if app_id_list:
            # vetting
            vet_rows = s.execute(
                select(TrustIDCheck.application_id).where(TrustIDCheck.application_id.in_(app_id_list))
            ).all()
            vetting_set = {v[0] for v in vet_rows}

            # esign
            esig_rows = s.execute(
                select(ESigRequest.application_id, ESigRequest.status)
                .where(ESigRequest.application_id.in_(app_id_list))
            ).all()
            for app_id, st in esig_rows:
                st = (st or "").lower()
                if st in ("sent", "delivered"):
                    issued_set.add(app_id)
                if st in ("signed", "completed"):
                    signed_set.add(app_id)

        # classify interviews
        for app_id, cand_id, job_id, sched_at, done_at, _role in apps_all:
            if sched_at and not done_at:
                sched_set.add(app_id)
            if done_at:
                done_set.add(app_id)

        # shortlist tile: not progressed to interview
        shortlist_pairs = {(sl["candidate_id"], sl["job"]["id"]) for sl in shortlisted}
        pair_to_app = {(a[1], a[2]): a[0] for a in apps_all}
        shortlist_effective = 0
        for (cid, jid) in shortlist_pairs:
            app_id = pair_to_app.get((cid, jid))
            if not app_id:
                shortlist_effective += 1
                continue
            if app_id in sched_set or app_id in done_set:
                continue
            shortlist_effective += 1

        tile_shortlist = shortlist_effective
        tile_interview_sched = len(sched_set)
        tile_interview_done = len(done_set)
        tile_vetting = len(vetting_set)
        tile_contract_issued = len(issued_set)
        tile_contract_signed = len(signed_set)

        # --- per-role metrics ---
        def norm_role(val: str) -> str:
            r = (val or "").strip()
            if r in ROLE_TYPES:
                return r
            return UNASSIGNED if r == "" else r

        # map every application id to its job role (from ALL apps)
        role_of_app = {}
        for app_id, _cid, _jid, _sched, _done, role_type in apps_all:
            role_of_app[app_id] = norm_role(role_type)

        def blank():
            return {"planned": 0, "declared": 0, "sched": 0, "done": 0,
                    "vetting": 0, "issued": 0, "signed": 0}

        # seed with roles that have a plan, carrying the planned counts
        role_metrics = {}
        for r, planned_cnt in planned_by_role.items():
            if planned_cnt > 0:
                rm = blank()
                rm["planned"] = planned_cnt
                role_metrics[r] = rm

        roles_from_activity = set()

        # declared (pending review only) — keep behaviour the same
        for r in declared_rows:
            role = role_of_app.get(r["app_id"], norm_role(r["job"]["role_type"]))
            m = role_metrics.setdefault(role, blank())
            m["declared"] += 1
            roles_from_activity.add(role)

        # count interview sched/done from ALL apps
        for app_id in sched_set:
            role = role_of_app.get(app_id, UNASSIGNED)
            role_metrics.setdefault(role, blank())["sched"] += 1
            roles_from_activity.add(role)

        for app_id in done_set:
            role = role_of_app.get(app_id, UNASSIGNED)
            role_metrics.setdefault(role, blank())["done"] += 1
            roles_from_activity.add(role)

        # vetting / issued / signed from ALL apps
        for app_id in vetting_set:
            role = role_of_app.get(app_id, UNASSIGNED)
            role_metrics.setdefault(role, blank())["vetting"] += 1
            roles_from_activity.add(role)

        for app_id in issued_set:
            role = role_of_app.get(app_id, UNASSIGNED)
            role_metrics.setdefault(role, blank())["issued"] += 1
            roles_from_activity.add(role)

        for app_id in signed_set:
            role = role_of_app.get(app_id, UNASSIGNED)
            role_metrics.setdefault(role, blank())["signed"] += 1
            roles_from_activity.add(role)

        display_roles = sorted(
            ({r for r, v in planned_by_role.items() if v > 0} | roles_from_activity),
            key=lambda x: (x != UNASSIGNED, ROLE_TYPES.index(x) if x in ROLE_TYPES else 999)
        )

        totals_row = {k: 0 for k in ["planned", "declared", "sched", "done", "vetting", "issued", "signed"]}
        for r in display_roles:
            m = role_metrics.get(r, {})
            for k in totals_row:
                totals_row[k] += int(m.get(k, 0) or 0)

        total_signed = totals_row["signed"]
        progress_pct = int(100 * total_signed / total_planned) if total_planned else 0

        # --- jobs table ---
        jobs_active = s.scalars(
            select(Job).where(Job.engagement_id == eng_id, Job.status == "Open").order_by(Job.created_at.desc())
        ).all()
        job_declared = {j.id: 0 for j in jobs_active}
        job_shortlisted = {j.id: 0 for j in jobs_active}

        if jobs_active:
            ids = [j.id for j in jobs_active]
            for jid, cnt in s.execute(
                select(Application.job_id, func.count()).where(Application.job_id.in_(ids)).group_by(Application.job_id)
            ).all():
                job_declared[jid] = int(cnt or 0)
            for jid, cnt in s.execute(
                select(Shortlist.job_id, func.count()).where(Shortlist.job_id.in_(ids)).group_by(Shortlist.job_id)
            ).all():
                job_shortlisted[jid] = int(cnt or 0)

        # --- render ---
        return render_template(
            "engagement_dashboard.html",
            engagement=engagement,
            planned_by_role=planned_by_role,
            declared_rows=declared_rows,
            interview_sched=interview_sched,
            interview_done=interview_done,
            vetting=[{"application_id": aid} for aid in vetting_set],  # optional: not used by template
            contract_issued=[{"application_id": aid} for aid in issued_set],
            contract_signed=[{"application_id": aid} for aid in signed_set],
            total_planned=total_planned,
            total_signed=total_signed,
            progress_pct=progress_pct,
            ROLE_TYPES=ROLE_TYPES,
            display_roles=display_roles,
            role_metrics=role_metrics,
            totals_row=totals_row,
            shortlist_count=shortlist_count,
            shortlisted=shortlisted,
            jobs_active=jobs_active,
            job_declared=job_declared,
            job_shortlisted=job_shortlisted,
            tile_shortlist=tile_shortlist,
            tile_interview_sched=tile_interview_sched,
            tile_interview_done=tile_interview_done,
            tile_vetting=tile_vetting,
            tile_contract_issued=tile_contract_issued,
            tile_contract_signed=tile_contract_signed,
        )

# -------- Plan Editor (dynamic fields) --------
from wtforms import SubmitField, IntegerField

def build_plan_form(initial_by_role: Dict[str, int]):
    """Create a WTForms class with one IntegerField per role."""
    class _PlanForm(FlaskForm):
        submit = SubmitField("Save plan")
    for role in ROLE_TYPES:
        fname = f"role_{slugify_role(role)}"
        setattr(_PlanForm, fname, IntegerField(role, default=int(initial_by_role.get(role, 0) or 0)))
    return _PlanForm

@app.route("/shortlist/add", methods=["POST"])
def shortlist_add():
    job_id = int(request.form.get("job_id", "0") or 0)
    cand_id = int(request.form.get("candidate_id", "0") or 0)

    if not job_id or not cand_id:
        flash("Pick a job and candidate to shortlist.", "warning")
        return redirect(url_for("resource_pool"))

    with Session(engine) as s:
        # Ensure both job and candidate exist
        job = s.scalar(select(Job).where(Job.id == job_id))
        cand = s.scalar(select(Candidate).where(Candidate.id == cand_id))
        if not job or not cand:
            flash("Job or Candidate not found.", "danger")
            return redirect(url_for("resource_pool", job_id=job_id))

        # Prevent duplicate shortlist entries
        already_exists = s.scalar(
            select(Shortlist.id)
            .where(Shortlist.job_id == job_id, Shortlist.candidate_id == cand_id)
            .limit(1)
        )

        if already_exists:
            flash(f"{cand.name} is already shortlisted for “{job.title}”.", "info")
        else:
            s.add(Shortlist(job_id=job_id, candidate_id=cand_id))
            s.commit()
            flash(f"Added {cand.name} to shortlist for “{job.title}”.", "success")

    return redirect(url_for("resource_pool", job_id=job_id))

@app.route("/shortlist/remove", methods=["POST"])
def shortlist_remove():
    job_id = int(request.form.get("job_id", "0") or 0)
    cand_id = int(request.form.get("candidate_id", "0") or 0)
    with Session(engine) as s:
        row = s.scalar(
            select(Shortlist).where(
                Shortlist.job_id == job_id,
                Shortlist.candidate_id == cand_id
            )
        )
        if row:
            s.delete(row)
            s.commit()
            flash("Removed from shortlist.", "success")
    return redirect(url_for("resource_pool", job_id=job_id))

@app.route("/engagement/<int:eng_id>/list/<section>")
def engagement_list(eng_id: int, section: str):
    # Simple shim so templates like url_for('engagement_list', ...) work.
    # It just jumps back to the dashboard and scrolls to an anchor matching `section`.
    # Valid examples used in your template: 'declared', 'shortlist', etc.
    return redirect(url_for("engagement_dashboard", eng_id=eng_id, _anchor=section))

# ---- Withdraw a job (and notify applicants not yet in vetting) ----
@app.route("/engagement/<int:eng_id>/jobs/<int:job_id>/withdraw", methods=["POST"])
def engagement_jobs_withdraw(eng_id: int, job_id: int):
    with Session(engine) as s:
        job = s.scalar(select(Job).where(Job.id == job_id, Job.engagement_id == eng_id))
        if not job: abort(404)

        job.status = "Withdrawn"
        s.add(job)

        app_rows = s.execute(
            select(Application.id, Application.candidate_id).where(Application.job_id == job_id)
        ).all()

        app_ids = [r[0] for r in app_rows]
        if app_ids:
            vetting_app_ids = {
                a_id for (a_id,) in s.execute(
                    select(TrustIDCheck.application_id)
                    .where(TrustIDCheck.application_id.in_(app_ids))
                    .group_by(TrustIDCheck.application_id)
                ).all()
            }
            notify_app_ids = [a_id for a_id in app_ids if a_id not in vetting_app_ids]

            if notify_app_ids:
                rows = s.execute(
                    select(Application.id, Candidate.email, Candidate.name)
                    .join(Candidate, Candidate.id == Application.candidate_id)
                    .where(Application.id.in_(notify_app_ids))
                ).all()
                for app_id, email, name in rows:
                    if email:
                        try:
                            send_email(
                                to_email=email,
                                subject=f"Update on your application — {job.title}",
                                html_body=(
                                    f"<p>Hi {name or 'there'},</p>"
                                    "<p>Thank you for your interest. The position has now been closed.</p>"
                                    "<p>We appreciate the time you took to apply and will keep your profile on file for future opportunities.</p>"
                                    "<p>Regards,<br>ATS Team</p>"
                                ),
                            )
                        except Exception as e:
                            current_app.logger.warning(f"Email send failed for app #{app_id} to {email}: {e}")

        s.commit()
        flash("Job withdrawn and notifications sent where applicable.", "success")

    return redirect(url_for("engagement_job_detail", eng_id=eng_id, job_id=job_id))

@app.route("/engagement/<int:eng_id>/plan", methods=["GET", "POST"])
def engagement_plan(eng_id):
    with Session(engine) as s:
        engagement = s.get(Engagement, eng_id)
        if not engagement:
            abort(404)

        if request.method == "POST":
            posted_version = int(request.form.get("plan_version") or engagement.plan_version or 1)
            new_version = posted_version + 1
            engagement.plan_version = new_version

            role_types  = request.form.getlist("role_type[]")
            counts      = request.form.getlist("planned_count[]")
            pays        = request.form.getlist("pay_rate[]")
            charges     = request.form.getlist("charge_rate[]")
            row_ids     = request.form.getlist("row_id[]")

            # We'll do in-place update/delete/insert for now.
            for i in range(len(role_types)):
                rid   = row_ids[i].strip()
                role  = role_types[i].strip()
                hc    = int(counts[i] or 0)
                pay   = int(pays[i] or 0)
                bill  = int(charges[i] or 0)

                if rid:
                    # existing row
                    deleted_flag = request.form.get(f"row_id_deleted_{rid}")
                    ep = s.get(EngagementPlan, int(rid))
                    if not ep:
                        continue
                    if deleted_flag == "1":
                        s.delete(ep)
                        continue

                    ep.role_type = role
                    ep.planned_count = hc
                    ep.pay_rate = pay
                    ep.charge_rate = bill
                    ep.rate = bill                     # keep legacy rate = charge
                    ep.version_int = new_version       # stamp version
                else:
                    # new row (only if there's actually something meaningful)
                    if role or hc or pay or bill:
                        ep = EngagementPlan(
                            engagement_id = engagement.id,
                            role_type = role,
                            planned_count = hc,
                            pay_rate = pay,
                            charge_rate = bill,
                            rate = bill,
                            version_int = new_version,
                        )
                        s.add(ep)

            s.commit()
            flash("Plan saved.", "success")
            return redirect(url_for("engagement_plan", eng_id=engagement.id))

        # GET render
        rows = s.scalars(
            select(EngagementPlan)
            .where(EngagementPlan.engagement_id == eng_id)
            .order_by(EngagementPlan.id.asc())
        ).all()

        role_types = s.scalars(
            select(RoleType).order_by(RoleType.name.asc())
        ).all()

    return render_template(
        "engagement_plan.html",   # <- this should be the template I provided
        engagement=engagement,
        rows=rows,
        role_types=role_types,
    )

# ---- Engagement-scoped Job detail ----
@app.route("/engagement/<int:eng_id>/jobs/<int:job_id>")
def engagement_job_detail(eng_id: int, job_id: int):
    with Session(engine) as s:
        job = s.scalar(select(Job).where(Job.id == job_id, Job.engagement_id == eng_id))
        if not job:
            abort(404)

        engagement = s.scalar(select(Engagement).where(Engagement.id == eng_id))
        if not engagement:
            abort(404)

        # Applications for this job
        app_rows = s.execute(
            select(Application, Candidate)
            .join(Candidate, Candidate.id == Application.candidate_id)
            .where(Application.job_id == job_id)
            .order_by(Application.created_at.desc())
        ).all()

        # simple shortlist lookups
        shortlisted_ids = {
            cid for (cid,) in s.execute(
                select(Shortlist.candidate_id).where(Shortlist.job_id == job_id)
            ).all()
        }

        items = []
        for a, c in app_rows:
            items.append({
                "app_id": a.id,
                "status": a.status,
                "ai_score": a.ai_score,
                "candidate": {"id": c.id, "name": c.name, "email": c.email},
                "shortlisted": c.id in shortlisted_ids,
                "interview_at": a.interview_scheduled_at,
                "interview_done_at": a.interview_completed_at,
                "created_at": a.created_at,
            })

    return render_template(
        "engagement_job_detail.html",  # create a small template or reuse a generic table
        engagement=engagement,
        job=job,
        items=items,
    )

# --- Shared renderer used by both global and engagement-scoped Applications ---
def _render_applications_table(
    q: str = "",
    job_id: Optional[str] = None,
    eng_id: Optional[int] = None,
    page: int = 1,
    per_page: int = 25,
    hide_closed: bool = True,                 # hide apps for non-Open jobs
    exclude_shortlisted_if_eng: bool = True,  # progressive pipeline in engagement scope
):
    with Session(engine) as s:
        base = (
            select(Application, Candidate, Job)
            .join(Candidate, Candidate.id == Application.candidate_id)
            .join(Job, Job.id == Application.job_id)
        )
        if eng_id:
            base = base.where(Job.engagement_id == eng_id, Job.status == "Open")
        if hide_closed:
            base = base.where(Job.status == "Open")

        if job_id and str(job_id).isdigit():
            base = base.where(Job.id == int(job_id))

        if q:
            like = f"%{q}%"
            base = base.where(or_(
                Candidate.name.ilike(like),
                Candidate.email.ilike(like),
                func.coalesce(Candidate.skills, "").ilike(like),
                Job.title.ilike(like),
            ))

        total = s.execute(base.with_only_columns(func.count()).order_by(None)).scalar() or 0
        rows = s.execute(base.order_by(Application.created_at.desc())
                         .limit(per_page).offset((page - 1)*per_page)).all()

        sl_pairs = set()
        if eng_id and exclude_shortlisted_if_eng:
            sl_pairs = {
                (cid, jid)
                for (cid, jid) in s.execute(
                    select(Shortlist.candidate_id, Shortlist.job_id)
                    .join(Job, Job.id == Shortlist.job_id)
                    .where(Job.engagement_id == eng_id, Job.status == "Open")
                ).all()
            }

        items = []
        for a, c, j in rows:
            already_sl = (c.id, j.id) in sl_pairs if sl_pairs else False
            items.append({
                "app": a,
                "cand": c,
                "job": j,
                "shortlisted": already_sl,  # your template can show a banner/disable button
            })

        pagination = {
            "page": page, "per_page": per_page, "total": total,
            "pages": max(1, (total + per_page - 1)//per_page),
        }

        tpl = "applications_engagement.html" if eng_id else "applications.html"
        engagement = s.get(Engagement, eng_id) if eng_id else None

    return render_template(tpl, q=q, job_id=job_id, eng_id=eng_id,
                           items=items, pagination=pagination, engagement=engagement)

@app.route("/applications")
def applications():
    q        = (request.args.get("q") or "").strip()
    job_id   = request.args.get("job_id")
    page     = max(1, int(request.args.get("page") or 1))
    per_page = max(5, min(100, int(request.args.get("per_page") or 25)))

    # Global view (no engagement filter), still hide closed jobs by default
    return _render_applications_table(
        q=q,
        job_id=job_id,
        eng_id=None,
        page=page,
        per_page=per_page,
        hide_closed=True,
        exclude_shortlisted_if_eng=False,  # not in an engagement scope
    )

# --- imports you likely already have ---
import datetime
from flask import abort, render_template, request
from sqlalchemy import or_, false

# If your session is named differently, adjust here:
# from your_module import session, engine, Application, Candidate, Job, Shortlist
# Ensure the models below are imported from wherever you declare them.

@app.route("/engagement/<int:eng_id>/applications")
def applications_for_engagement(eng_id: int):
    q = (request.args.get("q") or "").strip()

    raw_stage = (request.args.get("filter") or "declared").strip().lower()
    # Accept both "shortlist" and "shortlisted" (plus a few friendly aliases)
    stage_alias = {
        "declared": "declared", "apps": "declared", "applications": "declared",
        "shortlist": "shortlist", "shortlisted": "shortlist", "sl": "shortlist",
        "interview_sched": "interview_scheduled", "interview_scheduled": "interview_scheduled",
        "interview_done": "interview_completed", "interview_completed": "interview_completed",
        "vetting": "vetting",
        "contract_issued": "contract_issued", "issued": "contract_issued",
        "contract_signed": "contract_signed", "signed": "contract_signed",
    }
    stage_filter = stage_alias.get(raw_stage, "declared")

    with Session(engine) as s:
        engagement = s.get(Engagement, eng_id)
        if not engagement:
            abort(404)

        # All apps under this engagement (regardless of job status)
        apps_q = (
            s.query(Application)
             .join(Candidate, Candidate.id == Application.candidate_id)
             .join(Job, Job.id == Application.job_id)
             .filter(Job.engagement_id == eng_id)
        )

        if q:
            like = f"%{q}%"
            skills_clause = Candidate.skills.ilike(like) if hasattr(Candidate, "skills") else false()
            apps_q = apps_q.filter(or_(
                Candidate.name.ilike(like),
                Candidate.email.ilike(like),
                Job.title.ilike(like),
                skills_clause,
            ))

        app_rows = apps_q.all()

        # Shortlist membership for this engagement
        shortlist_pairs = {
            (srow.candidate_id, srow.job_id)
            for srow in (
                s.query(Shortlist)
                 .join(Job, Job.id == Shortlist.job_id)
                 .filter(Job.engagement_id == eng_id)
                 .all()
            )
        }

        # Latest e-sign status per application (scoped to this engagement)
        esig_rows = (
            s.query(ESigRequest)
             .join(Application, Application.id == ESigRequest.application_id)
             .join(Job, Job.id == Application.job_id)
             .filter(Job.engagement_id == eng_id)
             .order_by(ESigRequest.id.desc())
             .all()
        )
        esig_by_app: Dict[int, str] = {}
        for er in esig_rows:
            # keep the most recent seen
            esig_by_app.setdefault(er.application_id, (er.status or ""))

        # (optional) cache of apps that have any TrustID activity
        trust_app_ids = {
            t.application_id
            for t in s.query(TrustIDCheck)
                      .join(Application, Application.id == TrustIDCheck.application_id)
                      .join(Job, Job.id == Application.job_id)
                      .filter(Job.engagement_id == eng_id)
                      .all()
        }

        def infer_stage(app: Application) -> str:
            # Interview
            interview_sched = getattr(app, "interview_scheduled_at", None) or getattr(app, "interview_at", None)
            interview_done  = getattr(app, "interview_completed_at", None)

            # Per-application e-sign only
            es = (esig_by_app.get(app.id, "") or "").lower()
            if es in {"signed", "completed"}:
                return "contract_signed"
            if es in {"sent", "delivered", "viewed", "awaiting_signature"}:
                return "contract_issued"

            # Vetting if any TrustID row for this app
            if app.id in trust_app_ids:
                return "vetting"

            if interview_done:
                return "interview_completed"
            if interview_sched:
                return "interview_scheduled"

            # Shortlist strictly by (candidate_id, job_id) pair
            if (app.candidate_id, app.job_id) in shortlist_pairs:
                return "shortlist"

            return "declared"

        rows = []
        for appn in app_rows:
            stg = infer_stage(appn)
            if stg == stage_filter:
                rows.append({
                    "app": appn,
                    "cand": appn.candidate,
                    "job": appn.job,
                    "stage": stg,
                    "is_shortlisted": (appn.candidate_id, appn.job_id) in shortlist_pairs,
                })

        rows.sort(key=lambda r: getattr(r["app"], "created_at", datetime.datetime.min), reverse=True)

    return render_template(
        "applications_engagement.html",
        engagement=engagement,
        rows=rows,
        stage=stage_filter,
        q=q,
        engagement_finished=False,
    )

@app.route("/engagement/<int:eng_id>/financials")
def engagement_financials(eng_id):
    with Session(engine) as s:
        engagement = s.scalar(select(Engagement).where(Engagement.id == eng_id))
        if not engagement:
            abort(404)

        # Basic roll-ups from timesheets (if any)
        ts_rows = s.execute(
            select(Timesheet)
            .where(Timesheet.engagement_id == eng_id)
            .order_by(Timesheet.period_start.desc())
        ).scalars().all()

        stats = {
            "count": len(ts_rows),
            "draft": sum(1 for t in ts_rows if (t.status or "").lower() == "draft"),
            "submitted": sum(1 for t in ts_rows if (t.status or "").lower() == "submitted"),
            "approved": sum(1 for t in ts_rows if (t.status or "").lower() == "approved"),
            "rejected": sum(1 for t in ts_rows if (t.status or "").lower() == "rejected"),
            "hours_total": sum(int(t.hours or 0) for t in ts_rows),
            "hours_approved": sum(int(t.hours or 0) for t in ts_rows if (t.status or "").lower() == "approved"),
        }

        # You can expand this later with PO/budget data per engagement
        jobs = s.scalars(
            select(Job).where(Job.engagement_id == eng_id, Job.status == "Open").order_by(Job.created_at.desc())
        ).all()

    return render_template(
        "engagement_financials.html",
        engagement=engagement,
        stats=stats,
        jobs=jobs,
        timesheets=ts_rows,
    )

@app.route("/resource-pool")
def resource_pool():
    # Query params
    q = (request.args.get("q") or "").strip()
    has_cv = request.args.get("has_cv", "0") == "1"
    job_id = request.args.get("job_id")
    last_updated = request.args.get("last_updated") or ""  # "", "7","30","90","365"
    rank = request.args.get("rank") == "1"  # run heavy work for top N rows on page
    exclude_shortlisted = request.args.get("exclude_shortlisted", "0") == "1"
    page = max(1, int((request.args.get("page") or "1") or 1))
    per_page = max(5, min(100, int((request.args.get("per_page") or "25") or 25)))

    job = None
    job_id_int = None
    if job_id and str(job_id).isdigit():
        job_id_int = int(job_id)

    with Session(engine) as s:
        # Jobs for dropdown
        jobs = s.scalars(
            select(Job).options(selectinload(Job.engagement)).order_by(Job.created_at.desc())
        ).all()
        if job_id_int:
            job = s.scalar(select(Job).where(Job.id == job_id_int))

        # ---- Subqueries for last upload & doc count
        sub_last = (
            select(Document.candidate_id, func.max(Document.uploaded_at).label("last_uploaded"))
            .group_by(Document.candidate_id)
            .subquery()
        )
        sub_count = (
            select(Document.candidate_id, func.count().label("doc_count"))
            .group_by(Document.candidate_id)
            .subquery()
        )

        base = (
            select(Candidate, sub_last.c.last_uploaded, sub_count.c.doc_count)
            .outerjoin(sub_last, Candidate.id == sub_last.c.candidate_id)
            .outerjoin(sub_count, Candidate.id == sub_count.c.candidate_id)
        )

        # Free-text filter
        if q:
            like = f"%{q}%"
            base = base.where(
                or_(
                    Candidate.name.ilike(like),
                    Candidate.email.ilike(like),
                    Candidate.skills.ilike(like),
                )
            )

        if has_cv:
            base = base.where((sub_count.c.doc_count != None) & (sub_count.c.doc_count > 0))

        # Last updated (based on CV upload time)
        if last_updated in {"7", "30", "90", "365"}:
            days = int(last_updated)
            cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
            base = base.where((sub_last.c.last_uploaded != None) & (sub_last.c.last_uploaded >= cutoff))

        # Exclude candidates already shortlisted for the selected job
        if job and exclude_shortlisted:
            sl_ids_subq = select(Shortlist.candidate_id).where(Shortlist.job_id == job.id)
            base = base.where(Candidate.id.notin_(sl_ids_subq))

        # Count for pagination
        total_rows = s.execute(
            base.with_only_columns(func.count()).order_by(None)
        ).scalar() or 0

        # Sort most recently updated / created first
        base = base.order_by(func.coalesce(sub_last.c.last_uploaded, Candidate.created_at).desc())
        base = base.limit(per_page).offset((page - 1) * per_page)

        rows_db = s.execute(base).all()

        # Shortlisted lookup for the chosen job
        shortlisted_ids = set()
        if job:
            shortlisted_ids = {
                cid for (cid,) in s.execute(
                    select(Shortlist.candidate_id).where(Shortlist.job_id == job.id)
                ).all()
            }

        # "Shortlisted anywhere" lookup (for when no job is selected)
        shortlisted_any_ids = {
            cid for (cid,) in s.execute(select(Shortlist.candidate_id).distinct()).all()
        }

        rows = []
        # Heavy work cap
        top_n = 20
        heavy_budget = top_n if rank else 0
        heavy_used = 0

        for cand, last_uploaded, doc_count in rows_db:
            summary = ""
            score = None

            # Only do heavy work for the first N records when rank=1
            if heavy_used < heavy_budget:
                # Prefer CV text; fallback to skills string if no CV on file
                text_for_ai = ""
                latest_doc = _latest_doc_for_candidate(s, cand.id)
                if latest_doc:
                    text_for_ai = extract_cv_text(latest_doc) or ""

                used_fallback = False
                if not text_for_ai:
                    text_for_ai = (cand.skills or "").strip()
                    used_fallback = bool(text_for_ai)

                if text_for_ai:
                    # Score only when a job is selected (summary can be produced regardless)
                    if job:
                        score = int(ai_score_with_explanation(job.description or "", text_for_ai)["final"])
                    summary = ai_summarise(text_for_ai) or ""
                    if used_fallback:
                        summary = (summary + "\n\n(source: skills – no CV on file)").strip()
                    heavy_used += 1

            rows.append({
                "cand": cand,
                "last_uploaded": last_uploaded,          # retained (not shown in new table)
                "doc_count": int(doc_count or 0),        # retained (not shown in new table)
                "summary": summary,                      # may be empty if not in top_n or no text available
                "score": score,                          # None if no job or not processed
                "shortlisted": (cand.id in shortlisted_ids) if job else False,
                "shortlisted_any": (cand.id in shortlisted_any_ids),
            })

        # Pagination payload
        pagination = {
            "page": page,
            "per_page": per_page,
            "total": total_rows,
            "pages": max(1, (total_rows + per_page - 1) // per_page),
        }

        # Build simple list of job description top terms for hint chips
        def _top_terms(text: str, n: int = 12) -> List[str]:
            from collections import Counter
            words = _tokenize_words(text or "")
            cnt = Counter(words)
            return [w for (w, _) in cnt.most_common(n)]

        jd_terms = _top_terms(job.description) if job else []

    return render_template(
        "resource_pool.html",
        q=q,
        has_cv=has_cv,
        last_updated=last_updated,
        rows=rows,
        jobs=jobs,
        job=job,
        job_id=job.id if job else None,
        pagination=pagination,
        rank=rank,
        jd_terms=jd_terms,
    )

from flask import Response

@app.route("/resource-pool.csv")
def resource_pool_csv():
    q = (request.args.get("q") or "").strip()
    has_cv = request.args.get("has_cv", "0") == "1"
    job_id = request.args.get("job_id")
    last_updated = request.args.get("last_updated") or ""

    job = None
    job_id_int = None
    if job_id and str(job_id).isdigit():
        job_id_int = int(job_id)

    with Session(engine) as s:
        if job_id_int:
            job = s.scalar(select(Job).where(Job.id == job_id_int))

        sub_last = (
            select(Document.candidate_id, func.max(Document.uploaded_at).label("last_uploaded"))
            .group_by(Document.candidate_id)
            .subquery()
        )
        sub_count = (
            select(Document.candidate_id, func.count().label("doc_count"))
            .group_by(Document.candidate_id)
            .subquery()
        )

        stmt = (
            select(Candidate, sub_last.c.last_uploaded, sub_count.c.doc_count)
            .outerjoin(sub_last, Candidate.id == sub_last.c.candidate_id)
            .outerjoin(sub_count, Candidate.id == sub_count.c.candidate_id)
        )
        if q:
            like = f"%{q}%"
            stmt = stmt.where(
                or_(
                    Candidate.name.ilike(like),
                    Candidate.email.ilike(like),
                    Candidate.skills.ilike(like),
                )
            )
        if has_cv:
            stmt = stmt.where((sub_count.c.doc_count != None) & (sub_count.c.doc_count > 0))
        if last_updated in {"7","30","90","365"}:
            days = int(last_updated)
            cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
            stmt = stmt.where((sub_last.c.last_uploaded != None) & (sub_last.c.last_uploaded >= cutoff))

        stmt = stmt.order_by(func.coalesce(sub_last.c.last_uploaded, Candidate.created_at).desc())
        rows_db = s.execute(stmt).all()

        sio = StringIO()
        writer = csv.writer(sio)

        headers = ["Candidate ID", "Name", "Skills", "Last CV Upload"]
        if job:
            headers += ["Match Score (0-100)", "AI Summary", "Matched Job"]
        else:
            headers += ["AI Summary"]
        writer.writerow(headers)

        for cand, last_uploaded, doc_count in rows_db:
            latest_doc = _latest_doc_for_candidate(s, cand.id)
            cv_text = extract_cv_text(latest_doc) if latest_doc else ""
            summary = ""
            score = ""
            if cv_text:
                summary = ai_summarise(cv_text) or ""
                if job:
                    result = ai_score_with_explanation(job.description or "", cv_text)
                    score = int(result.get("final", 0)) if result else 0

            row = [
                cand.id,
                cand.name or "",
                (cand.skills or "").replace("\n"," ").strip(),
                last_uploaded.isoformat() if last_uploaded else "",
            ]
            if job:
                row += [score, summary.replace("\n", " ").strip(), job.title]
            else:
                row += [summary.replace("\n", " ").strip()]
            writer.writerow(row)

    csv_bytes = sio.getvalue().encode("utf-8")
    return Response(
        csv_bytes,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=resource_pool.csv"}
    )

# -------- Taxonomy: view (read-only) --------
@app.route("/taxonomy")
def taxonomy():
    with Session(engine) as s:
        roles = s.scalars(select(TaxonomyCategory).where(TaxonomyCategory.type=="role").order_by(TaxonomyCategory.name.asc())).all()
        subjects = s.scalars(select(TaxonomyCategory).where(TaxonomyCategory.type=="subject").order_by(TaxonomyCategory.name.asc())).all()
        # eager-load tags
        for c in roles + subjects:
            c._tags = s.scalars(select(TaxonomyTag).where(TaxonomyTag.category_id==c.id).order_by(TaxonomyTag.tag.asc())).all()
    return render_template("taxonomy.html", roles=roles, subjects=subjects)

# -------- Taxonomy: manage (add/edit/delete) --------
@app.route("/taxonomy/manage", methods=["GET"])
def taxonomy_manage():
    cat_form = TaxCategoryForm()
    tag_form = TaxTagForm()
    with Session(engine) as s:
        cats = s.scalars(select(TaxonomyCategory).order_by(TaxonomyCategory.type.asc(), TaxonomyCategory.name.asc())).all()
        tag_form.category_id.choices = [(c.id, f"[{c.type}] {c.name}") for c in cats]
        # group for UI
        roles = [c for c in cats if c.type=="role"]
        subjects = [c for c in cats if c.type=="subject"]
        tags_by_cat = {}
        for c in cats:
            tags_by_cat[c.id] = s.scalars(select(TaxonomyTag).where(TaxonomyTag.category_id==c.id).order_by(TaxonomyTag.tag.asc())).all()
    return render_template("taxonomy_manage.html",
                           roles=roles, subjects=subjects,
                           tags_by_cat=tags_by_cat,
                           cat_form=cat_form, tag_form=tag_form)

@app.route("/taxonomy/category/add", methods=["POST"])
def taxonomy_category_add():
    form = TaxCategoryForm()
    if not form.validate_on_submit():
        flash("Provide a type and category name.", "warning")
        return redirect(url_for("taxonomy_manage"))
    with Session(engine) as s:
        s.add(TaxonomyCategory(type=form.type.data, name=form.name.data.strip()))
        s.commit()
    flash("Category added.", "success")
    return redirect(url_for("taxonomy_manage"))

@app.route("/taxonomy/category/<int:cat_id>/rename", methods=["POST"])
def taxonomy_category_rename(cat_id):
    new_name = (request.form.get("name") or "").strip()
    if not new_name:
        flash("New name required.", "warning")
        return redirect(url_for("taxonomy_manage"))
    with Session(engine) as s:
        c = s.scalar(select(TaxonomyCategory).where(TaxonomyCategory.id==cat_id))
        if not c:
            abort(404)
        c.name = new_name
        s.commit()
    flash("Category renamed.", "success")
    return redirect(url_for("taxonomy_manage"))

@app.route("/taxonomy/category/<int:cat_id>/delete", methods=["POST"])
def taxonomy_category_delete(cat_id):
    with Session(engine) as s:
        c = s.scalar(select(TaxonomyCategory).where(TaxonomyCategory.id==cat_id))
        if not c:
            abort(404)
        s.delete(c)  # cascades to tags
        s.commit()
    flash("Category deleted.", "success")
    return redirect(url_for("taxonomy_manage"))

@app.route("/taxonomy/tag/add", methods=["POST"])
def taxonomy_tag_add():
    form = TaxTagForm()
    # rebuild choices to allow validation in POST
    with Session(engine) as s:
        cats = s.scalars(select(TaxonomyCategory)).all()
    form.category_id.choices = [(c.id, f"[{c.type}] {c.name}") for c in cats]

    if not form.validate_on_submit():
        flash("Select a category and enter a tag.", "warning")
        return redirect(url_for("taxonomy_manage"))
    with Session(engine) as s:
        # prevent dup within same category (case-insensitive)
        exists = s.scalar(
            select(TaxonomyTag).where(
                TaxonomyTag.category_id==form.category_id.data,
                func.lower(TaxonomyTag.tag)==func.lower(form.tag.data.strip())
            )
        )
        if exists:
            flash("Tag already exists in that category.", "info")
            return redirect(url_for("taxonomy_manage"))
        s.add(TaxonomyTag(category_id=form.category_id.data, tag=form.tag.data.strip()))
        s.commit()
    flash("Tag added.", "success")
    return redirect(url_for("taxonomy_manage"))

@app.route("/taxonomy/tag/<int:tag_id>/delete", methods=["POST"])
def taxonomy_tag_delete(tag_id):
    with Session(engine) as s:
        t = s.scalar(select(TaxonomyTag).where(TaxonomyTag.id==tag_id))
        if not t:
            abort(404)
        s.delete(t)
        s.commit()
    flash("Tag deleted.", "success")
    return redirect(url_for("taxonomy_manage"))

@app.route("/action/taxonomy/retag_all", methods=["POST"])
def taxonomy_retag_all():
    """
    Re-tag candidates in batches: POST /action/taxonomy/retag_all?batch=500&offset=0&overwrite=0
    - batch:    how many to process
    - offset:   starting row (by id order)
    - overwrite: if 1, replace Candidate.skills with derived tags + old content; else only append missing tags
    """
    batch     = max(1, min(5000, int(request.args.get("batch", "500") or 500)))
    offset    = max(0, int(request.args.get("offset", "0") or 0))
    overwrite = request.args.get("overwrite", "0") == "1"

    updated, examined = 0, 0
    with Session(engine) as s:
        # load term list once
        groups = _get_subject_term_set(s)
        term_list = [t for t in groups.get("__all__", [])]
        # page over candidates by id
        cands = s.scalars(
            select(Candidate).order_by(Candidate.id.asc()).offset(offset).limit(batch)
        ).all()

        for cand in cands:
            examined += 1
            text_lc = _collect_text_for_candidate(s, cand)
            if not text_lc:
                continue
            # role & tags
            role = _normalise_role(text_lc)
            tags = _derive_subject_tags(text_lc, term_list)

            # persist: keep it simple — write tags into Candidate.skills for visibility in UI
            current = (cand.skills or "").strip()
            new_tag_str = ", ".join(sorted(tags, key=str.lower)) if tags else ""
            if overwrite:
                merged = new_tag_str
                if current:
                    # keep any freeform skills too
                    merged = (new_tag_str + (" | " if new_tag_str and current else "") + current).strip()
                cand.skills = merged or current
            else:
                # append tags that aren't already present (case-insensitive)
                existing_tokens = {w.strip().lower() for w in re.split(r"[,/|;]", current) if w.strip()}
                to_add = [t for t in tags if t.lower() not in existing_tokens]
                if to_add:
                    cand.skills = (current + (" | " if current else "") + ", ".join(to_add)).strip()

            # (optional) store normalised role into candidate.skills prefix for now
            if role:
                # add role token if missing
                if role.lower() not in (cand.skills or "").lower():
                    cand.skills = (f"{role} | " + (cand.skills or "")).strip(" |")

            updated += 1

        s.commit()

    flash(f"Re-tagged {updated} / examined {examined}. Offset={offset}, batch={batch}.", "success")
    return redirect(url_for("taxonomy"))
    

@app.route("/action/taxonomy/retag_one/<int:cand_id>", methods=["POST"])
def taxonomy_retag_one(cand_id):
    """Re-tag just one candidate (handy button next to a row)."""
    with Session(engine) as s:
        cand = s.scalar(select(Candidate).where(Candidate.id == cand_id))
        if not cand:
            flash("Candidate not found", "warning")
            return redirect(request.referrer or url_for("resource_pool"))

        groups = _get_subject_term_set(s)
        term_list = [t for t in groups.get("__all__", [])]
        text_lc = _collect_text_for_candidate(s, cand)
        role = _normalise_role(text_lc)
        tags = _derive_subject_tags(text_lc, term_list)

        current = (cand.skills or "").strip()
        existing_tokens = {w.strip().lower() for w in re.split(r"[,/|;]", current) if w.strip()}
        to_add = [t for t in tags if t.lower() not in existing_tokens]
        if role and role.lower() not in existing_tokens and role.lower() not in (cand.skills or "").lower():
            cand.skills = (f"{role} | " + current).strip(" |")
            current = cand.skills
        if to_add:
            cand.skills = (current + (" | " if current else "") + ", ".join(to_add)).strip()

        s.commit()

    flash(f"Re-tagged candidate #{cand_id}.", "success")
    return redirect(request.referrer or url_for("resource_pool"))

# --- Candidate ⇄ Tag: add ---
@app.post("/candidate/<int:cand_id>/tag/add")
def candidate_tag_add(cand_id: int):
    tag_id = int((request.form.get("tag_id") or "0") or 0)
    if not tag_id:
        flash("Pick a tag to add.", "warning")
        return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=request.args.get("job_id")))

    with Session(engine) as s:
        cand = s.get(Candidate, cand_id)
        tag  = s.get(TaxonomyTag, tag_id)
        if not cand or not tag:
            flash("Invalid candidate or tag.", "danger")
            return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=request.args.get("job_id")))

        # prevent duplicates
        exists = s.scalar(
            select(CandidateTag).where(
                CandidateTag.candidate_id == cand_id,
                CandidateTag.tag_id == tag_id,
            )
        )
        if not exists:
            s.add(CandidateTag(candidate_id=cand_id, tag_id=tag_id))

            # Optional: reflect in Candidate.skills (append if not already there, case-insensitive)
            skills = (cand.skills or "").strip()
            tokens = [t.strip() for t in re.split(r"[,\|/;]", skills) if t.strip()]
            lower = {t.lower() for t in tokens}
            if tag.tag.lower() not in lower:
                tokens.append(tag.tag)
                cand.skills = ", ".join(tokens)

            s.commit()

    return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=request.args.get("job_id")))

# --- Candidate ⇄ Tag: remove ---
@app.post("/candidate/<int:cand_id>/tag/remove")
def candidate_tag_remove(cand_id: int):
    tag_id = int((request.form.get("tag_id") or "0") or 0)

    with Session(engine) as s:
        rel = s.scalar(
            select(CandidateTag).where(
                CandidateTag.candidate_id == cand_id,
                CandidateTag.tag_id == tag_id,
            )
        )
        if rel:
            s.delete(rel)

            # Optional: also remove from Candidate.skills
            cand = s.get(Candidate, cand_id)
            tag  = s.get(TaxonomyTag, tag_id)
            if cand and tag and (cand.skills or "").strip():
                parts = [p.strip() for p in re.split(r"[,\|/;]", cand.skills) if p.strip()]
                cand.skills = ", ".join([p for p in parts if p.lower() != tag.tag.lower()])

            s.commit()

    return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=request.args.get("job_id")))

# ---------- Candidate-level card actions ----------

@app.post("/action/onboarding_email/candidate/<int:cand_id>")
def action_onboarding_email_candidate(cand_id):
    """Send a general onboarding email and stamp candidate.onboarded_at."""
    with Session(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            abort(404)

        # If there is a latest application, mention the job in the email.
        appn = _latest_application_for_candidate(s, cand_id)
        job = s.get(Job, appn.job_id) if appn else None

        link = f"{APP_BASE_URL}/candidate/{cand.id}"
        subj = f"Onboarding — {job.title}" if job else "Onboarding"
        html = f"""
        <h3>Welcome to onboarding</h3>
        <p>Hi {cand.name}, we'll guide you through vetting next.</p>
        <p>You can check status here: <a href="{link}">{link}</a></p>
        """
        send_email(cand.email, subj, html)

        cand.onboarded_at = datetime.datetime.utcnow()
        s.commit()

    flash("Onboarding email sent.", "success")
    return redirect(url_for("candidate_profile", cand_id=cand_id))


@app.post("/action/esign/candidate/<int:cand_id>")
def action_esign_candidate(cand_id):
    """Kick off an e-sign flow if there is an application; otherwise just mark status."""
    with Session(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            abort(404)

        appn = _latest_application_for_candidate(s, cand_id)
        if appn:
            # Reuse your application flow
            # (call the function directly to avoid round-trips)
            try:
                job = s.get(Job, appn.job_id)
                subject = f"Contract — {job.title if job else 'Agreement'}"
                message = "Please review and sign your contract."

                if ESIGN_PROVIDER == "dropbox_sign":
                    req_id = send_esign_dropbox_sign(appn.id, cand.name, cand.email, subject, message)
                elif ESIGN_PROVIDER == "docusign":
                    req_id = send_esign_docusign(appn.id, cand.name, cand.email, subject, message)
                else:
                    raise RuntimeError("Unsupported ESIGN_PROVIDER")

                es = s.scalar(select(ESigRequest).where(ESigRequest.application_id == appn.id))
                if not es:
                    es = ESigRequest(application_id=appn.id, provider=ESIGN_PROVIDER,
                                     request_id=req_id, status="Sent", sent_at=datetime.datetime.utcnow())
                    s.add(es)
                else:
                    es.provider = ESIGN_PROVIDER
                    es.request_id = req_id
                    es.status = "Sent"
                    es.sent_at = datetime.datetime.utcnow()
                cand.esign_status = "Sent"
                s.commit()
            except Exception as e:
                flash(f"E-sign send failed: {e}", "danger")
                return redirect(url_for("candidate_profile", cand_id=cand_id))
        else:
            # No application — just mark status so the card shows activity.
            cand.esign_status = "Sent"
            s.commit()

    flash("E-signature initiated.", "success")
    return redirect(url_for("candidate_profile", cand_id=cand_id))

@app.post("/candidate/<int:cand_id>/summarise", endpoint="cand_summarise")
def candidate_summarise(cand_id):
    with Session(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            abort(404)

        # Prefer latest CV that’s actually a CV
        doc = s.scalar(
            select(Document)
            .where(Document.candidate_id == cand_id, Document.doc_type == "cv")
            .order_by(Document.uploaded_at.desc())
        )

        cv_text = extract_cv_text(doc) if doc else ""
        source_text = cv_text or (cand.skills or "")
        if not source_text:
            flash("No CV or skills text available to summarise.", "warning")
            return redirect(url_for("candidate_profile", cand_id=cand_id))

        # Write to an actual persisted column
        cand.ai_summary = ai_summarise(source_text) or ""
        s.commit()

    flash("AI summary regenerated.", "success")
    return redirect(url_for("candidate_profile", cand_id=cand_id))

@app.post("/candidate/<int:cand_id>/skills/update")
def candidate_skills_update(cand_id):
    new_skills = (request.form.get("skills") or "").strip()
    with Session(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            abort(404)
        cand.skills = new_skills
        s.commit()
    flash("Skills updated.", "success")
    return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=request.args.get("job_id")))

@app.post("/action/esign_status/candidate/<int:cand_id>")
def action_esign_status_candidate(cand_id):
    """Refresh candidate-level e-sign status (via latest application if present)."""
    with Session(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            abort(404)

        appn = _latest_application_for_candidate(s, cand_id)
        if not appn:
            flash("No application to poll. Status unchanged.", "info")
            return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=request.args.get("job_id")))

        es = s.scalar(select(ESigRequest).where(ESigRequest.application_id == appn.id))
        if not es:
            flash("No e-sign request found for the latest application.", "warning")
            return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=request.args.get("job_id")))

        try:
            if es.provider == "dropbox_sign":
                status = poll_esign_dropbox_sign(es.request_id)
            elif es.provider == "docusign":
                status = poll_esign_docusign(es.request_id)
            else:
                status = "Unknown"
        except Exception as e:
            flash(f"E-sign status failed: {e}", "danger")
            return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=request.args.get("job_id")))

        es.status = status
        if status in {"Signed", "Completed"}:
            es.signed_at = datetime.datetime.utcnow()
        cand.esign_status = status
        s.commit()

    flash(f"E-sign status: {status}", "info")
    return redirect(url_for("candidate_profile", cand_id=cand_id, job_id=request.args.get("job_id")))

@app.post("/action/trustid/candidate/<int:cand_id>")
def action_trustid_candidate(cand_id):
    """Start TrustID checks at candidate level; stamp the dates locally.
       If there is an application, also create a real TrustIDCheck row."""
    do_rtw = bool(request.form.get("rtw"))
    do_idv = bool(request.form.get("idv", True))
    do_dbs = bool(request.form.get("dbs"))

    with Session(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            abort(404)

        # Stamp local candidate dates immediately so the card reflects activity
        now = datetime.datetime.utcnow()
        if do_rtw:
            cand.trustid_rtw_date = now
        if do_idv:
            cand.trustid_idv_date = now
        if do_dbs:
            cand.trustid_dbs_date = now

        # If there is a latest application, also kick off a real TrustID app + row
        appn = _latest_application_for_candidate(s, cand_id)

        if appn:
            payload = {
                "external_ref": f"CAND-{cand.id}-APP-{appn.id}",
                "candidate": {"name": cand.name, "email": cand.email},
                "checks": {"rtw": do_rtw, "idv": do_idv, "dbs": do_dbs},
                "webhooks": {"result": f"{APP_BASE_URL}/webhook/trustid"},
            }
            try:
                resp = requests.post(
                    f"{TRUSTID_BASE_URL}/apps",
                    headers=trustid_headers(),
                    data=json.dumps(payload),
                    timeout=15,
                )
                if resp.status_code >= 300:
                    raise RuntimeError(f"TrustID error: {resp.status_code} {resp.text}")
                data = resp.json()
                trust_app_id = data.get("id", "") or data.get("application_id", "")
                s.add(TrustIDCheck(
                    application_id=appn.id,
                    rtw=do_rtw, idv=do_idv, dbs=do_dbs,
                    trustid_application_id=trust_app_id,
                    status="InProgress",
                ))
            except Exception as e:
                current_app.logger.warning(f"TrustID create failed for candidate #{cand.id}: {e}")
                flash(f"TrustID create failed: {e}", "danger")
                # even if TrustID API failed, keep local timestamps
                s.commit()
                return redirect(url_for("candidate_profile", cand_id=cand_id))

        s.commit()

    flash("TrustID checks started and candidate record updated.", "success")
    return redirect(url_for("candidate_profile", cand_id=cand_id))

@app.post("/action/request_updated_cv/candidate/<int:cand_id>")
def action_request_updated_cv_candidate(cand_id):
    """Send a generic 'please upload updated CV' link and timestamp."""
    with Session(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            abort(404)
        link = f"{APP_BASE_URL}/candidate/{cand.id}/upload_cv"
        html = f"""
        <h3>Request for updated CV</h3>
        <p>Hi {cand.name}, please upload an updated CV here:</p>
        <p><a href="{link}">{link}</a></p>
        """
        send_email(cand.email, "Please upload an updated CV", html)
        cand.updated_cv_requested_at = datetime.datetime.utcnow()
        s.commit()

    flash("CV update request sent.", "success")
    return redirect(url_for("candidate_profile", cand_id=cand_id))

@app.route("/configuration", methods=["GET"])
def configuration():
    alias_form = RoleAliasForm()
    with Session(engine) as s:
        # role aliases
        aliases = s.execute(text("SELECT id, canonical, alias FROM role_aliases ORDER BY canonical, alias")).all()
        # taxonomy data
        cats = s.scalars(select(TaxonomyCategory).order_by(TaxonomyCategory.type.asc(), TaxonomyCategory.name.asc())).all()
        tags_by_cat = {
            c.id: s.scalars(select(TaxonomyTag).where(TaxonomyTag.category_id==c.id).order_by(TaxonomyTag.tag.asc())).all()
            for c in cats
        }
    return render_template("configuration.html",
                           alias_form=alias_form,
                           aliases=aliases,
                           cats=cats,
                           tags_by_cat=tags_by_cat,
                           ROLE_TYPES=ROLE_TYPES)

@app.post("/config/role-alias/add")
def config_role_alias_add():
    form = RoleAliasForm()
    if not form.validate_on_submit():
        flash("Pick a canonical role and enter an alias.", "warning")
        return redirect(url_for("configuration"))
    canonical = form.canonical.data.strip()
    alias = form.alias.data.strip()
    with Session(engine) as s:
        # prevent dup (case-insensitive)
        exists = s.execute(
            text("""SELECT 1 FROM role_aliases 
                    WHERE lower(canonical)=:c AND lower(alias)=:a LIMIT 1"""),
            {"c": canonical.lower(), "a": alias.lower()}
        ).first()
        if exists:
            flash("That alias already exists for the selected canonical role.", "info")
        else:
            s.execute(text("INSERT INTO role_aliases(canonical, alias) VALUES(:c,:a)"),
                      {"c": canonical, "a": alias})
            s.commit()
            flash("Alias added.", "success")
    return redirect(url_for("configuration"))

@app.post("/opportunities/<int:opp_id>/convert")
def opportunity_convert(opp_id):
    with Session(engine) as s:
        opp = s.get(Opportunity, opp_id)
        if not opp:
            flash("Opportunity not found.", "warning")
            return redirect(url_for("opportunities_"))

        e = create_engagement_for_opportunity(s, opp)
        if e is None and (opp.stage or "").strip().lower() != "closed won":
            flash("Opportunity must be Closed Won to create an engagement.", "warning")
            return redirect(url_for("opportunities_"))

        s.commit()
        if e:
            flash(f"Engagement {e.ref} created.", "success")
            return redirect(url_for("engagement_dashboard", eng_id=e.id))
        else:
            # Already existed (idempotent case)
            existing = s.execute(
                text("SELECT id, ref FROM engagements WHERE opportunity_id=:oid"),
                {"oid": opp.id}
            ).first()
            if existing:
                flash(f"Engagement {existing[1]} already exists.", "info")
                return redirect(url_for("engagement_dashboard", eng_id=existing[0]))
            flash("Nothing to do.", "info")
            return redirect(url_for("opportunities_"))

@app.post("/config/role-alias/delete")
def config_role_alias_delete():
    alias_id = int((request.form.get("id") or 0))
    if not alias_id:
        flash("Missing alias id.", "warning")
        return redirect(url_for("configuration"))
    with Session(engine) as s:
        s.execute(text("DELETE FROM role_aliases WHERE id=:i"), {"i": alias_id})
        s.commit()
    flash("Alias removed.", "success")
    return redirect(url_for("configuration"))

@app.get("/uploads/cvs/<path:fname>", endpoint="download_cv")
def download_cv(fname: str):
    # Always serve from CV_DIR; strip any sneaky path bits
    safe_name = _basename_safe(fname)
    return send_from_directory(CV_DIR, safe_name, as_attachment=False)

@app.get("/sumsub/sdk.js")
def sumsub_sdk_proxy():
    """
    Proxies the Sumsub WebSDK JS from the CDN to avoid ad-block/VPN/CORS issues in dev.
    """
    last_exc = None
    for url in SUMSUB_SDK_URLS:
        try:
            r = requests.get(url, timeout=10)
            if r.ok and r.content and b"SNSWebSdk" in r.content:
                resp = make_response(r.content, 200)
                resp.headers["Content-Type"] = "application/javascript; charset=utf-8"
                resp.headers["Cache-Control"] = "public, max-age=3600"
                return resp
        except Exception as e:
            last_exc = e

    # If all mirrors failed, return a clear error so the page can show it
    msg = f"// Failed to fetch Sumsub SDK. Last error: {last_exc!r}" if last_exc else "// Failed to fetch Sumsub SDK."
    resp = make_response(msg, 502)
    resp.headers["Content-Type"] = "application/javascript; charset=utf-8"
    return resp

@app.get("/job/<int:job_id>/public-link")
def job_public_link(job_id):
    with Session(engine) as s:
        job = s.get(Job, job_id)
        if not job or (job.status or "").lower() != "open":
            abort(404)
        return redirect(url_for("public.public_job_detail", token=job.public_token))

@app.get("/engagement/<int:eng_id>/jobs")
def engagement_jobs(eng_id):
    with Session(engine) as s:
        eng = s.get(Engagement, eng_id)
        if not eng:
            abort(404)
        jobs = s.scalars(
            select(Job)
            .where(Job.engagement_id == eng_id, Job.status == "Open")
            .order_by(Job.created_at.desc())
        ).all()
    return render_template("eng_jobs_list.html", engagement=eng, jobs=jobs)

@app.route("/engagement/<int:eng_id>/jobs/create", methods=["GET","POST"])
def engagement_jobs_create(eng_id):
    with Session(engine) as s:
        eng = s.get(Engagement, eng_id)
        if not eng:
            abort(404)

        form = JobForm()
        # lock the engagement selection to this engagement
        form.engagement_id.choices = [(eng.id, f"{eng.name} ({eng.client})")]
        form.engagement_id.data = eng.id

        if form.validate_on_submit():
            j = Job(
                engagement_id=eng.id,
                title=form.title.data,
                description=form.description.data,
                role_type=form.role_type.data or "",
                location=form.location.data or "",
                salary_range=form.salary_range.data or "",
                status="Open",
            )
            s.add(j)
            s.commit()
            flash("Job created for this engagement.", "success")
            return redirect(url_for("engagement_jobs", eng_id=eng.id))

    return render_template("eng_job_create.html", engagement=eng, form=form)

@app.post("/jobs/<int:job_id>/withdraw")
def job_withdraw(job_id):
    """
    Mark job as Withdrawn and email all *applicants* who have NOT entered vetting
    (i.e., no TrustIDCheck row for their application).
    """
    with Session(engine) as s:
        job = s.get(Job, job_id)
        if not job:
            abort(404)

        # If already withdrawn, do nothing
        was_withdrawn = (job.status or "").lower() == "withdrawn"
        job.status = "Withdrawn"

        # Find applications with NO TrustIDCheck rows
        apps = s.execute(
            select(Application, Candidate)
            .join(Candidate, Candidate.id == Application.candidate_id)
            .where(Application.job_id == job.id)
        ).all()

        # Build a set of application_ids that have vetting rows
        app_ids = [a.id for a, _ in apps]
        vetted_app_ids = set()
        if app_ids:
            vetted_app_ids = {
                app_id for (app_id,) in s.execute(
                    select(TrustIDCheck.application_id)
                    .where(TrustIDCheck.application_id.in_(app_ids))
                    .limit(100000)
                ).all()
            }

        # Email only those *without* vetting
        emailed = 0
        for appn, cand in apps:
            if appn.id in vetted_app_ids:
                continue
            # polite note
            html = f"""
              <p>Hi {cand.name},</p>
              <p>Thank you for your interest in <strong>{job.title}</strong>. This position has now been closed.</p>
              <p>We appreciate your time and will keep your details on file for future opportunities.</p>
              <p>Best regards,<br>Talent Team</p>
            """
            try:
                if cand.email:
                    send_email(cand.email, f"Update on your application — {job.title}", html)
                    emailed += 1
            except Exception as e:
                current_app.logger.warning("Withdraw email failed for %s: %s", cand.email, e)

        s.commit()

    msg = "Job withdrawn."
    if emailed:
        msg += f" Notified {emailed} applicant(s) with no vetting started."
    flash(msg, "success")
    # bounce back to the engagement's jobs list if we can infer it; else jobs page
    try:
        return redirect(url_for("engagement_jobs", eng_id=job.engagement_id))
    except Exception:
        return redirect(url_for("jobs"))

# --- SINGLE canonical shortlist endpoint (ensure there is only ONE of these) ---
@app.post("/shortlist")
def candidate_shortlist_action():
    from flask import g
    g.allow_shortlist = True
    next_url = request.form.get("next") or request.referrer
    app_id = (request.form.get("app_id") or "").strip()
    job_id = (request.form.get("job_id") or "").strip()
    cand_id = (request.form.get("candidate_id") or "").strip()

    with Session(engine) as s:
        job = candidate = engagement = None

        if app_id.isdigit():
            appn = s.get(Application, int(app_id))
            if not appn:
                flash("Application not found.", "warning")
                return redirect(next_url or url_for("applications"))
            job = s.get(Job, appn.job_id)
            candidate = s.get(Candidate, appn.candidate_id)
        else:
            if not (job_id.isdigit() and cand_id.isdigit()):
                flash("Missing job/candidate parameters.", "warning")
                return redirect(next_url or url_for("index"))
            job = s.get(Job, int(job_id))
            candidate = s.get(Candidate, int(cand_id))

        if not job or not candidate:
            flash("Job or candidate not found.", "warning")
            return redirect(next_url or url_for("index"))

        engagement = s.get(Engagement, job.engagement_id) if job.engagement_id else None
        eng_active = ((engagement.status if engagement else "") or "").strip().lower() in {"active","in-flight","in progress"}
        if not eng_active:
            flash("Engagement is not active; cannot shortlist.", "warning")
            return redirect(next_url or (url_for("engagement_dashboard", eng_id=engagement.id) if engagement else url_for("index")))

        if not _job_is_open(job):
            flash(f"Job is {job.status or 'not open'}; cannot shortlist.", "warning")
            return redirect(next_url or url_for("engagement_dashboard", eng_id=engagement.id))

        exists_row = s.execute(
            select(Shortlist.id).where(Shortlist.job_id==job.id, Shortlist.candidate_id==candidate.id).limit(1)
        ).first()

        if exists_row:
            flash("Already shortlisted for this job.", "info")
        else:
            s.add(Shortlist(job_id=job.id, candidate_id=candidate.id))
            s.commit()
            flash(f"Shortlisted {candidate.name} for “{job.title}”.", "success")

    if next_url:  # return to the Applications list you came from
        return redirect(next_url)
    if engagement:
        return redirect(url_for("applications_for_engagement", eng_id=engagement.id))
    return redirect(url_for("applications"))

@app.route("/candidate/login", methods=["GET", "POST"])
def candidate_login():
    """
    Collect email → email a time-limited magic link.
    If candidate doesn't exist yet, we create on first successful login.
    """
    form = CandidateLoginForm()
    nxt = request.args.get("next") or url_for("index")
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        token = _signer().dumps({"email": email, "next": nxt})
        link = f"{APP_BASE_URL}/candidate/magic?token={token}"
        try:
            send_email(
                to_email=email,
                subject="Your secure sign-in link",
                html_body=f"""
                    <p>Click to sign in:</p>
                    <p><a href="{link}">{link}</a></p>
                    <p>This link will expire in 20 minutes.</p>
                """
            )
        except Exception as e:
            flash(f"Failed to send login link: {e}", "danger")
            return render_template("candidate_login.html", form=form, next=nxt)
        flash("Check your email for a sign-in link.", "info")
        return redirect(url_for("index"))
    return render_template("candidate_login.html", form=form, next=nxt)

@app.route("/candidate/magic")
def candidate_magic():
    token = request.args.get("token", "")
    try:
        data = _signer().loads(token, max_age=20*60)  # 20 minutes
    except SignatureExpired:
        flash("This link has expired. Please request a new one.", "warning")
        return redirect(url_for("candidate_login"))
    except BadSignature:
        flash("Invalid sign-in link.", "danger")
        return redirect(url_for("candidate_login"))

    email = (data.get("email") or "").strip().lower()
    nxt = data.get("next") or url_for("index")

    if not email:
        flash("Missing email in link.", "danger")
        return redirect(url_for("candidate_login"))

    with Session(engine) as s:
        cand = s.scalar(select(Candidate).where(func.lower(Candidate.email) == email))
        if not cand:
            # create a candidate shell record on first sign-in
            cand = Candidate(name=email.split("@")[0].title(), email=email)
            s.add(cand)
            s.flush()
            s.commit()

        # set candidate session
        session["candidate_id"] = cand.id
        session["candidate_email"] = cand.email

    flash("Signed in as candidate.", "success")
    return redirect(nxt)

@app.route("/candidate/logout")
def candidate_logout():
    session.pop("candidate_id", None)
    session.pop("candidate_email", None)
    flash("Signed out.", "info")
    return redirect(url_for("index"))

@app.route("/candidate/<int:cand_id>/upload_cv", methods=["GET", "POST"])
def candidate_upload_cv(cand_id):
    form = UploadCVForm()
    with Session(engine) as s:
        cand = s.get(Candidate, cand_id)
        if not cand:
            abort(404)

        if form.validate_on_submit():
            file = request.files.get("cv")
            if not file or not file.filename:
                flash("Please choose a CV file.", "warning")
                return render_template("candidate_upload_cv.html", form=form, cand=cand)

            try:
                stored_basename = save_cv(file)                     # ← basename only
                original_name   = file.filename or stored_basename
            except Exception as e:
                flash(f"Upload failed: {e}", "danger")
                return render_template("candidate_upload_cv.html", form=form, cand=cand)

            # Save document
            doc = Document(
                candidate_id=cand.id,
                doc_type="cv",
                filename=stored_basename,
                original_name=original_name,
            )
            s.add(doc)
            s.flush()

            # Optional: rebuild AI summary + tags from the new CV (non-blocking if you prefer)
            try:
                _rebuild_ai_summary_and_tags(s, cand, doc=doc, job=None, appn=None)
            except Exception as e:
                current_app.logger.warning(f"Post-upload AI/retag failed for cand #{cand.id}: {e}")

            s.commit()
            flash("CV uploaded successfully.", "success")
            return redirect(url_for("candidate_profile", cand_id=cand.id))

    return render_template("candidate_upload_cv.html", form=form, cand=cand)

# --- MFA/2FA Routes for Admin Users ---

@app.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    """Setup MFA for current admin user."""
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
                    text("UPDATE users SET mfa_secret = :secret, mfa_enabled_at = :now WHERE id = :user_id"),
                    {"secret": secret, "now": datetime.datetime.utcnow(), "user_id": current_user.id}
                )
                s.commit()
            
            session.pop("mfa_setup_secret", None)
            session["mfa_verified"] = True
            
            audit_log("mfa_enabled", user_id=current_user.id)
            flash("MFA enabled successfully!", "success")
            return redirect(url_for("index"))
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
            session.permanent = True
            
            audit_log("mfa_verified", user_id=current_user.id)
            
            next_url = request.args.get("next") or url_for("index")
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
    with Session(engine) as s:
        s.execute(
            text("UPDATE users SET mfa_secret = NULL, mfa_enabled_at = NULL WHERE id = :user_id"),
            {"user_id": current_user.id}
        )
        s.commit()
    
    session.pop("mfa_verified", None)
    audit_log("mfa_disabled", user_id=current_user.id)
    
    flash("MFA disabled.", "info")
    return redirect(url_for("index"))

# --- Magic Link Authentication for Candidates ---

@app.route("/candidate/send-magic-link", methods=["POST"])
@limiter.limit("3 per minute")
def send_candidate_magic_link():
    """Send magic link to candidate email."""
    from app import Candidate
    
    email = request.form.get("email", "").strip().lower()
    
    if not email:
        flash("Please provide your email address.", "danger")
        return redirect(url_for("candidate_login"))
    
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
    
    return redirect(url_for("candidate_login"))


@app.route("/candidate/login/<token>")
def candidate_magic_login(token):
    """Authenticate candidate using magic link token."""
    from app import Candidate
    
    candidate_id, email = verify_magic_link_token(token, max_age=3600)
    
    if not candidate_id:
        audit_log("magic_link_invalid", details={"token": token[:10]})
        flash("Invalid or expired login link.", "danger")
        return redirect(url_for("candidate_login"))
    
    with Session(engine) as s:
        candidate = s.get(Candidate, candidate_id)
        
        if not candidate or candidate.email.lower() != email.lower():
            audit_log("magic_link_mismatch", user_id=candidate_id)
            flash("Invalid login link.", "danger")
            return redirect(url_for("candidate_login"))
        
        # Set session
        session["candidate_id"] = candidate.id
        session["candidate_email"] = candidate.email
        session.permanent = True
        
        audit_log("candidate_login_magic_link", user_id=candidate.id)
        flash(f"Welcome back, {candidate.name}!", "success")
    
    return redirect(url_for("candidate_profile", cand_id=candidate.id))


def send_magic_link_email(to_email, magic_link):
    """Send magic link email to candidate."""
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

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = WorkerLoginForm()
    nxt = request.args.get("next") or url_for("index")
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        pw = form.password.data
        with Session(engine) as s:
            row = s.execute(text("SELECT id, name, email, pw_hash, mfa_secret FROM users WHERE lower(email)=:e"), {"e": email}).first()
            if not row or not row[3] or not check_password_hash(row[3], pw):
                audit_log("login_failed", details={"email": email})
                flash("Invalid email or password.", "danger")
                return render_template("auth_login.html", form=form, next=nxt)
            class _Obj: pass
            obj = _Obj(); obj.id, obj.name, obj.email = row[0], row[1], row[2]
            login_user(WorkerUser(obj))
            
            audit_log("user_login", user_id=obj.id)
            
            # Check if MFA is enabled
            mfa_secret = row[4] if len(row) > 4 else None
            if mfa_secret:
                # Redirect to MFA verification
                session["mfa_verified"] = False
                return redirect(url_for("mfa_verify", next=nxt))
            
        flash("Signed in.", "success")
        return redirect(nxt)
    return render_template("auth_login.html", form=form, next=nxt)

@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        audit_log("user_logout", user_id=current_user.id)
        logout_user()
    # also clear candidate session in case they shared a browser
    session.pop("candidate_id", None)
    session.pop("candidate_email", None)
    session.pop("mfa_verified", None)
    flash("Signed out.", "info")
    return redirect(url_for("index"))

# OPTIONAL: simple worker signup (disable in prod or restrict to admins)
@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def signup():
    form = WorkerSignupForm()
    if form.validate_on_submit():
        with Session(engine) as s:
            exists = s.execute(text("SELECT 1 FROM users WHERE lower(email)=:e"), {"e": form.email.data.strip().lower()}).first()
            if exists:
                flash("That email is already registered.", "warning")
                return render_template("auth_signup.html", form=form)
            s.execute(text("""
                INSERT INTO users(name, email, pw_hash)
                VALUES (:n, :e, :p)
            """), {
                "n": form.name.data.strip(),
                "e": form.email.data.strip().lower(),
                "p": generate_password_hash(form.password.data)
            })
            s.commit()
        flash("Account created. Please sign in.", "success")
        return redirect(url_for("login"))
    return render_template("auth_signup.html", form=form)

if __name__ == "__main__":
    app.run(debug=True)