"""
NIPT Result Interpretation Software (NRIS) v2.0 - Enhanced Edition
By AzizElGhezal
---------------------------
Advanced clinical genetics dashboard with authentication, analytics, 
PDF reports, visualizations, and comprehensive audit logging.
"""

import sqlite3
import json
import io
import hashlib
import secrets
import re
from datetime import datetime, timedelta
from typing import Tuple, List, Dict, Any, Optional
import base64

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
import PyPDF2

# ==================== CONFIGURATION ====================
DB_FILE = "nipt_registry_v2.db"
CONFIG_FILE = "nris_config.json"

DEFAULT_CONFIG = {
    'QC_THRESHOLDS': {
        'MIN_CFF': 3.5,
        'GC_RANGE': [37.0, 44.0],
        'MIN_UNIQ_RATE': 68.0,
        'MAX_ERROR_RATE': 1.0,
        'QS_LIMIT_NEG': 1.7,
        'QS_LIMIT_POS': 2.0
    },
    'PANEL_READ_LIMITS': {
        "NIPT Basic": 5,
        "NIPT Standard": 7,
        "NIPT Plus": 12,
        "NIPT Pro": 20
    },
    'CLINICAL_THRESHOLDS': {
        'TRISOMY_LOW': 2.58,
        'TRISOMY_AMBIGUOUS': 6.0,
        'SCA_THRESHOLD': 4.5,
        'RAT_POSITIVE': 8.0,
        'RAT_AMBIGUOUS': 4.5
    }
}

# ==================== DATABASE FUNCTIONS ====================

def init_database() -> None:
    """Enhanced database with audit logging and user management."""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                role TEXT DEFAULT 'technician',
                created_at TEXT,
                last_login TEXT
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS patients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mrn_id TEXT UNIQUE,
                full_name TEXT,
                age INTEGER,
                weight_kg REAL,
                height_cm INTEGER,
                bmi REAL,
                weeks INTEGER,
                clinical_notes TEXT,
                created_at TEXT,
                created_by INTEGER,
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER,
                panel_type TEXT,
                qc_status TEXT,
                qc_details TEXT,
                qc_advice TEXT,
                qc_metrics_json TEXT,
                t21_res TEXT,
                t18_res TEXT,
                t13_res TEXT,
                sca_res TEXT,
                cnv_json TEXT,
                rat_json TEXT,
                full_z_json TEXT,
                final_summary TEXT,
                created_at TEXT,
                created_by INTEGER,
                FOREIGN KEY(patient_id) REFERENCES patients(id),
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
        ''')

        # Migration: Add qc_metrics_json column if it doesn't exist
        try:
            c.execute("ALTER TABLE results ADD COLUMN qc_metrics_json TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                timestamp TEXT,
                ip_address TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] == 0:
            admin_hash = hash_password("admin123")
            c.execute("""
                INSERT INTO users (username, password_hash, full_name, role, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, ("admin", admin_hash, "System Administrator", "admin", datetime.now().isoformat()))

def log_audit(action: str, details: str, user_id: Optional[int] = None) -> None:
    """Log user actions for compliance."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO audit_log (user_id, action, details, timestamp, ip_address)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, action, details, datetime.now().isoformat(), "local"))
    except:
        pass

def hash_password(password: str) -> str:
    """Hash password with salt."""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}${pwd_hash}"

def verify_password(password: str, hash_str: str) -> bool:
    """Verify password against hash."""
    try:
        salt, pwd_hash = hash_str.split('$')
        return hashlib.sha256((password + salt).encode()).hexdigest() == pwd_hash
    except:
        return False

def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """Authenticate user and return user data."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT id, username, password_hash, full_name, role FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            
            if row and verify_password(password, row[2]):
                c.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.now().isoformat(), row[0]))
                log_audit("LOGIN", f"User {username} logged in", row[0])
                return {'id': row[0], 'username': row[1], 'name': row[3], 'role': row[4]}
    except:
        pass
    return None

def load_config() -> Dict:
    """Load configuration from file or return defaults."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return DEFAULT_CONFIG.copy()

def save_config(config: Dict) -> bool:
    """Save configuration to file."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except:
        return False

# ==================== ANALYSIS FUNCTIONS ====================

def validate_inputs(reads: float, cff: float, gc: float, age: int) -> List[str]:
    """Validate clinical inputs."""
    errors = []
    if reads < 0 or reads > 100: errors.append("Reads must be 0-100M")
    if cff < 0 or cff > 50: errors.append("Cff must be 0-50%")
    if gc < 0 or gc > 100: errors.append("GC must be 0-100%")
    if age < 15 or age > 60: errors.append("Age must be 15-60")
    return errors

def check_qc_metrics(config: Dict, panel: str, reads: float, cff: float, gc: float, 
                    qs: float, uniq: float, error: float, is_positive: bool) -> Tuple[str, List[str], str]:
    """Enhanced QC with configurable thresholds."""
    thresholds = config['QC_THRESHOLDS']
    issues, advice = [], []
    
    min_reads = config['PANEL_READ_LIMITS'].get(panel, 5)
    if reads < min_reads:
        issues.append(f"HARD: Reads {reads}M < {min_reads}M")
        advice.append("Resequencing")

    if cff < thresholds['MIN_CFF']:
        issues.append(f"HARD: Cff {cff}% < {thresholds['MIN_CFF']}%")
        advice.append("Resample")

    gc_range = thresholds['GC_RANGE']
    if not (gc_range[0] <= gc <= gc_range[1]):
        issues.append(f"HARD: GC {gc}% out of range")
        advice.append("Re-library")

    qs_limit = thresholds['QS_LIMIT_POS'] if is_positive else thresholds['QS_LIMIT_NEG']
    if qs >= qs_limit:
        issues.append(f"HARD: QS {qs} >= {qs_limit}")
        advice.append("Re-library")

    if uniq < thresholds['MIN_UNIQ_RATE']:
        issues.append(f"SOFT: UniqueRate {uniq}% Low")
    if error > thresholds['MAX_ERROR_RATE']:
        issues.append(f"SOFT: ErrorRate {error}% High")

    status = "FAIL" if any("HARD" in i for i in issues) else ("WARNING" if issues else "PASS")
    advice_str = " / ".join(set(advice)) if advice else "None"
    
    return status, issues, advice_str

def analyze_trisomy(config: Dict, z_score: float, chrom: str) -> Tuple[str, str]:
    """Returns (result, risk_level)."""
    thresholds = config['CLINICAL_THRESHOLDS']
    if pd.isna(z_score): return "Invalid Data", "UNKNOWN"
    
    if z_score < thresholds['TRISOMY_LOW']: 
        return "Low Risk", "LOW"
    if z_score < thresholds['TRISOMY_AMBIGUOUS']: 
        return f"High Risk (Z:{z_score:.2f}) -> Re-library", "HIGH"
    return "POSITIVE -> Report Positive", "POSITIVE"

def analyze_sca(config: Dict, sca_type: str, z_xx: float, z_xy: float, cff: float) -> Tuple[str, str]:
    """Enhanced SCA analysis."""
    if cff < config['QC_THRESHOLDS']['MIN_CFF']: 
        return "INVALID (Cff < 3.5%)", "INVALID"
    
    threshold = config['CLINICAL_THRESHOLDS']['SCA_THRESHOLD']
    
    if sca_type == "XX": return "Negative (Female)", "LOW"
    if sca_type == "XY": return "Negative (Male)", "LOW"
    
    if sca_type == "XO":
        return ("POSITIVE (Turner XO)", "POSITIVE") if z_xx >= threshold else (f"Ambiguous XO", "HIGH")
    
    if sca_type == "XXX":
        return ("POSITIVE (Triple X)", "POSITIVE") if z_xx >= threshold else (f"Ambiguous XXX", "HIGH")
        
    if sca_type in ["XXY", "XYY"]: 
        return f"POSITIVE ({sca_type})", "POSITIVE"
    
    return "Ambiguous SCA", "HIGH"

def analyze_rat(config: Dict, chrom: int, z_score: float) -> Tuple[str, str]:
    """RAT analysis."""
    thresholds = config['CLINICAL_THRESHOLDS']
    if z_score >= thresholds['RAT_POSITIVE']: return "POSITIVE", "POSITIVE"
    if z_score > thresholds['RAT_AMBIGUOUS']: return "Ambiguous -> Re-library", "HIGH"
    return "Low Risk", "LOW"

def analyze_cnv(size: float, ratio: float) -> Tuple[str, float, str]:
    """CNV analysis."""
    if size >= 10: threshold = 6.0
    elif size > 7: threshold = 8.0
    elif size > 3.5: threshold = 10.0
    else: threshold = 12.0
    
    if ratio >= threshold:
        return f"High Risk -> Re-library", threshold, "HIGH"
    return "Low Risk", threshold, "LOW"

def check_duplicate_patient(mrn: str) -> Tuple[bool, Optional[Dict]]:
    """Check if a patient with this MRN already exists. Returns (exists, patient_info)."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT p.id, p.full_name, p.mrn_id, p.age, p.weeks, COUNT(r.id) as result_count
                FROM patients p
                LEFT JOIN results r ON r.patient_id = p.id
                WHERE p.mrn_id = ?
                GROUP BY p.id
            """, (mrn,))
            row = c.fetchone()
            if row:
                return True, {
                    'id': row[0],
                    'name': row[1],
                    'mrn': row[2],
                    'age': row[3],
                    'weeks': row[4],
                    'result_count': row[5]
                }
    except Exception:
        pass
    return False, None

def save_result(patient: Dict, results: Dict, clinical: Dict, full_z: Optional[Dict] = None,
                qc_metrics: Optional[Dict] = None, allow_duplicate: bool = True) -> Tuple[int, str]:
    """Save with audit logging. Returns (result_id, message)."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()

            c.execute("SELECT id, full_name FROM patients WHERE mrn_id = ?", (patient['id'],))
            existing = c.fetchone()

            if existing:
                patient_db_id = existing[0]
                existing_name = existing[1]
                if not allow_duplicate:
                    return 0, f"Patient with ID '{patient['id']}' already exists in registry as '{existing_name}'"
            else:
                c.execute("""
                    INSERT INTO patients
                    (mrn_id, full_name, age, weight_kg, height_cm, bmi, weeks, clinical_notes, created_at, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    patient['id'], patient['name'], patient['age'], patient['weight'],
                    patient['height'], patient['bmi'], patient['weeks'], patient['notes'],
                    datetime.now().isoformat(), st.session_state.user['id']
                ))
                patient_db_id = c.lastrowid

            # Prepare QC metrics JSON
            qc_metrics_json = json.dumps(qc_metrics) if qc_metrics else "{}"

            c.execute("""
                INSERT INTO results
                (patient_id, panel_type, qc_status, qc_details, qc_advice, qc_metrics_json,
                 t21_res, t18_res, t13_res, sca_res,
                 cnv_json, rat_json, full_z_json, final_summary, created_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                patient_db_id, results['panel'], results['qc_status'],
                str(results['qc_msgs']), results['qc_advice'], qc_metrics_json,
                clinical['t21'], clinical['t18'], clinical['t13'], clinical['sca'],
                json.dumps(clinical['cnv_list']), json.dumps(clinical['rat_list']),
                json.dumps(full_z) if full_z else "{}", clinical['final'],
                datetime.now().isoformat(), st.session_state.user['id']
            ))
            result_id = c.lastrowid

            log_audit("SAVE_RESULT", f"Created result {result_id}", st.session_state.user['id'])
            return result_id, "Success"
    except Exception as e:
        st.error(f"Database error: {e}")
        return 0, str(e)

def update_patient(patient_id: int, data: Dict) -> Tuple[bool, str]:
    """Update patient information."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("""
                UPDATE patients
                SET full_name = ?, age = ?, weight_kg = ?, height_cm = ?, bmi = ?,
                    weeks = ?, clinical_notes = ?
                WHERE id = ?
            """, (
                data['name'], data['age'], data['weight'], data['height'],
                data['bmi'], data['weeks'], data['notes'], patient_id
            ))
            log_audit("UPDATE_PATIENT", f"Updated patient {patient_id}", st.session_state.user['id'])
            return True, "Patient updated successfully"
    except Exception as e:
        return False, str(e)

def get_patient_details(patient_id: int) -> Optional[Dict]:
    """Get full patient details including all results."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT p.id, p.mrn_id, p.full_name, p.age, p.weight_kg, p.height_cm,
                       p.bmi, p.weeks, p.clinical_notes, p.created_at
                FROM patients p
                WHERE p.id = ?
            """, (patient_id,))
            row = c.fetchone()
            if row:
                return {
                    'id': row[0],
                    'mrn': row[1],
                    'name': row[2],
                    'age': row[3],
                    'weight': row[4],
                    'height': row[5],
                    'bmi': row[6],
                    'weeks': row[7],
                    'notes': row[8],
                    'created_at': row[9]
                }
    except Exception:
        pass
    return None

def delete_record(report_id: int) -> Tuple[bool, str]:
    """Delete with audit."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT patient_id FROM results WHERE id = ?", (report_id,))
            row = c.fetchone()
            if not row: return False, "Not found"
            
            c.execute("DELETE FROM results WHERE id = ?", (report_id,))
            log_audit("DELETE", f"Deleted {report_id}", st.session_state.user['id'])
            return True, f"Deleted {report_id}"
    except Exception as e:
        return False, str(e)

# ==================== PDF IMPORT FUNCTIONS ====================

def extract_data_from_pdf(pdf_file, filename: str = "") -> Optional[Dict]:
    """Extract comprehensive patient and test data from PDF report.

    Extracts:
    - Patient demographics (name, MRN, age, weight, height, BMI, gestational weeks)
    - Sample information (collection date, laboratory, referring physician)
    - Pregnancy information (singleton/multiple, indication for testing)
    - Sequencing metrics (reads, Cff, GC%, QS, unique rate, error rate)
    - Z-scores for all 22 autosomes plus sex chromosomes
    - SCA type detection with karyotype patterns
    - CNV findings with size, ratio, and chromosomal location
    - RAT findings with chromosome and Z-score
    - QC status and final interpretation
    - Clinical notes and recommendations
    """
    try:
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        for page in pdf_reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"

        # Clean up text - normalize whitespace and line endings
        text = re.sub(r'\s+', ' ', text)
        text_lines = text.replace('. ', '.\n').replace(': ', ': ')

        # Initialize comprehensive data structure
        data = {
            'source_file': filename,
            'patient_name': '',
            'mrn': '',
            'age': 0,
            'weight': 0.0,
            'height': 0,
            'bmi': 0.0,
            'weeks': 0,
            'panel': 'NIPT Standard',
            'reads': 0.0,
            'cff': 0.0,
            'gc': 0.0,
            'qs': 0.0,
            'unique_rate': 0.0,
            'error_rate': 0.0,
            'z_scores': {},
            'sca_type': 'XX',
            'cnv_findings': [],
            'rat_findings': [],
            'qc_status': '',
            'final_result': '',
            'notes': '',
            # New comprehensive fields
            'sample_date': '',
            'report_date': '',
            'laboratory': '',
            'referring_physician': '',
            'indication': '',
            'pregnancy_type': 'Singleton',
            'sample_type': '',
            'fetal_sex': '',
            'risk_t21': '',
            'risk_t18': '',
            'risk_t13': '',
            'sensitivity_t21': '',
            'specificity_t21': '',
            'ppv_t21': '',
            'npv_t21': '',
            'microdeletion_results': [],
            'extraction_confidence': 'HIGH'
        }

        # ===== PATIENT DEMOGRAPHICS =====
        # Extract patient name (multiple patterns for different report formats)
        name_patterns = [
            r'(?:Patient|Patient\s+Name|Name)[:\s]+([A-Za-z][A-Za-z\s\-\'\.]+?)(?:\s*(?:MRN|ID|Age|DOB|Date|\||,|\n|$))',
            r'Full\s+Name[:\s]+([A-Za-z][A-Za-z\s\-\'\.]+?)(?:\s*(?:MRN|\n|$))',
            r'Name\s*:\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)',
            r'(?:Mrs?\.?|Ms\.?|Dr\.?)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)',
        ]
        for pattern in name_patterns:
            name_match = re.search(pattern, text, re.IGNORECASE)
            if name_match:
                name = name_match.group(1).strip()
                # Clean up name - remove trailing numbers, special chars
                name = re.sub(r'[\d\|\,]+$', '', name).strip()
                if len(name) > 2 and ' ' in name or len(name) > 5:
                    data['patient_name'] = name
                    break

        # Extract MRN / Patient ID (multiple patterns)
        mrn_patterns = [
            r'MRN[:\s#]+([A-Za-z0-9\-]+)',
            r'Medical\s+Record\s+(?:Number|No\.?)[:\s]+([A-Za-z0-9\-]+)',
            r'(?:Patient\s+)?ID[:\s#]+([A-Za-z0-9\-]{4,})',
            r'File\s+(?:Number|No\.?)[:\s]+([A-Za-z0-9\-]+)',
            r'Accession[:\s#]+([A-Za-z0-9\-]+)',
            r'Sample\s+ID[:\s]+([A-Za-z0-9\-]+)',
            r'Case\s+(?:Number|No\.?|ID)[:\s]+([A-Za-z0-9\-]+)',
        ]
        for pattern in mrn_patterns:
            mrn_match = re.search(pattern, text, re.IGNORECASE)
            if mrn_match:
                data['mrn'] = mrn_match.group(1).strip()
                break

        # Extract age (with validation)
        age_patterns = [
            r'(?:Maternal\s+)?Age[:\s]+(\d{1,2})\s*(?:years?|yrs?|y)?(?:\s|,|\.|$)',
            r'Age\s*\((?:years?|yrs?)\)[:\s]+(\d{1,2})',
            r'(\d{2})\s*(?:years?|yrs?)\s+old',
        ]
        for pattern in age_patterns:
            age_match = re.search(pattern, text, re.IGNORECASE)
            if age_match:
                age = int(age_match.group(1))
                if 15 <= age <= 60:  # Reasonable maternal age range
                    data['age'] = age
                    break

        # Extract weight (with unit conversion if needed)
        weight_patterns = [
            r'Weight[:\s]+(\d+\.?\d*)\s*(?:kg|KG|kilograms?)',
            r'Weight[:\s]+(\d+\.?\d*)\s*(?:lbs?|pounds?)',  # Will need conversion
            r'(?:Maternal\s+)?Weight[:\s]+(\d+\.?\d*)',
        ]
        for pattern in weight_patterns:
            weight_match = re.search(pattern, text, re.IGNORECASE)
            if weight_match:
                weight = float(weight_match.group(1))
                # Convert lbs to kg if detected
                if 'lb' in pattern.lower() or weight > 150:
                    weight = weight * 0.453592
                if 30 <= weight <= 200:  # Reasonable weight range in kg
                    data['weight'] = round(weight, 1)
                    break

        # Extract height (with unit conversion if needed)
        height_patterns = [
            r'Height[:\s]+(\d{2,3})\s*(?:cm|CM|centimeters?)',
            r'Height[:\s]+(\d)[\'′](\d{1,2})[\"″]?',  # feet'inches" format
            r'(?:Maternal\s+)?Height[:\s]+(\d{2,3})',
        ]
        for pattern in height_patterns:
            height_match = re.search(pattern, text, re.IGNORECASE)
            if height_match:
                if "'" in pattern or "′" in pattern:
                    # Convert feet/inches to cm
                    feet = int(height_match.group(1))
                    inches = int(height_match.group(2)) if height_match.group(2) else 0
                    height = int((feet * 12 + inches) * 2.54)
                else:
                    height = int(height_match.group(1))
                if 100 <= height <= 220:  # Reasonable height range in cm
                    data['height'] = height
                    break

        # Extract BMI
        bmi_patterns = [
            r'BMI[:\s]+(\d+\.?\d*)',
            r'Body\s+Mass\s+Index[:\s]+(\d+\.?\d*)',
        ]
        for pattern in bmi_patterns:
            bmi_match = re.search(pattern, text, re.IGNORECASE)
            if bmi_match:
                bmi = float(bmi_match.group(1))
                if 15 <= bmi <= 60:  # Reasonable BMI range
                    data['bmi'] = round(bmi, 1)
                    break

        # Calculate BMI if weight and height available but BMI not extracted
        if not data['bmi'] and data['weight'] > 0 and data['height'] > 0:
            data['bmi'] = round(data['weight'] / ((data['height']/100)**2), 1)

        # Extract gestational weeks (multiple patterns)
        weeks_patterns = [
            r'(?:Gestational\s+Age|Gest\.?\s+Age|GA)[:\s]+(\d{1,2})\s*(?:\+\s*\d+)?(?:\s*weeks?|\s*wks?)?',
            r'(\d{1,2})\s*(?:\+\s*\d+)?\s*weeks?\s*(?:gestation|pregnant|GA)',
            r'Weeks?\s*(?:of\s+)?(?:Gestation|Pregnancy)[:\s]+(\d{1,2})',
            r'(?:at\s+)?(\d{1,2})\s*weeks?\s*(?:gestation)?',
        ]
        for pattern in weeks_patterns:
            weeks_match = re.search(pattern, text, re.IGNORECASE)
            if weeks_match:
                weeks = int(weeks_match.group(1))
                if 9 <= weeks <= 42:  # Reasonable gestational age for NIPT
                    data['weeks'] = weeks
                    break

        # ===== SAMPLE & REPORT INFORMATION =====
        # Extract sample collection date
        date_patterns = [
            r'(?:Sample|Collection|Draw)\s+Date[:\s]+(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4})',
            r'(?:Date\s+)?(?:Collected|Drawn)[:\s]+(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4})',
            r'Collection[:\s]+(\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2})',
        ]
        for pattern in date_patterns:
            date_match = re.search(pattern, text, re.IGNORECASE)
            if date_match:
                data['sample_date'] = date_match.group(1).strip()
                break

        # Extract report date
        report_date_patterns = [
            r'(?:Report|Reported)\s+Date[:\s]+(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4})',
            r'Date\s+(?:of\s+)?Report[:\s]+(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4})',
        ]
        for pattern in report_date_patterns:
            date_match = re.search(pattern, text, re.IGNORECASE)
            if date_match:
                data['report_date'] = date_match.group(1).strip()
                break

        # Extract laboratory name
        lab_patterns = [
            r'(?:Laboratory|Lab)[:\s]+([A-Za-z][A-Za-z\s\-&]+?)(?:\n|$|Address)',
            r'Performed\s+(?:at|by)[:\s]+([A-Za-z][A-Za-z\s\-&]+?)(?:\n|$)',
            r'([A-Za-z]+\s+(?:Genetics|Genomics|Laboratory|Lab|Diagnostics)(?:\s+[A-Za-z]+)?)',
        ]
        for pattern in lab_patterns:
            lab_match = re.search(pattern, text, re.IGNORECASE)
            if lab_match:
                data['laboratory'] = lab_match.group(1).strip()[:100]
                break

        # Extract referring physician
        physician_patterns = [
            r'(?:Referring|Ordering)\s+(?:Physician|Provider|Doctor|MD)[:\s]+(?:Dr\.?\s+)?([A-Za-z][A-Za-z\s\-\.]+)',
            r'Physician[:\s]+(?:Dr\.?\s+)?([A-Za-z][A-Za-z\s\-\.]+?)(?:\n|$|,)',
            r'Ordered\s+[Bb]y[:\s]+(?:Dr\.?\s+)?([A-Za-z][A-Za-z\s\-\.]+)',
        ]
        for pattern in physician_patterns:
            phys_match = re.search(pattern, text, re.IGNORECASE)
            if phys_match:
                data['referring_physician'] = phys_match.group(1).strip()[:100]
                break

        # Extract indication for testing
        indication_patterns = [
            r'(?:Indication|Reason)[:\s]+(.+?)(?:\n|$|Panel|Test)',
            r'(?:Clinical\s+)?Indication[:\s]+(.+?)(?:\n|$)',
            r'Referred\s+for[:\s]+(.+?)(?:\n|$)',
        ]
        for pattern in indication_patterns:
            ind_match = re.search(pattern, text, re.IGNORECASE)
            if ind_match:
                data['indication'] = ind_match.group(1).strip()[:200]
                break

        # Extract pregnancy type (singleton/twin/multiple)
        if re.search(r'(?:twin|twins|multiple|dichorionic|monochorionic|dizygotic|monozygotic)', text, re.IGNORECASE):
            data['pregnancy_type'] = 'Multiple'
        elif re.search(r'singleton', text, re.IGNORECASE):
            data['pregnancy_type'] = 'Singleton'

        # Extract sample type
        sample_patterns = [
            r'(?:Sample|Specimen)\s+Type[:\s]+([A-Za-z\s]+?)(?:\n|$|,)',
            r'(?:Blood|Plasma|Serum|cfDNA)',
        ]
        for pattern in sample_patterns:
            sample_match = re.search(pattern, text, re.IGNORECASE)
            if sample_match:
                data['sample_type'] = sample_match.group(1).strip() if sample_match.lastindex else sample_match.group(0)
                break

        # ===== SEQUENCING METRICS =====
        # Extract panel type
        panel_patterns = [
            r'Panel[:\s]+(NIPT\s+\w+)',
            r'Test\s+(?:Type|Name)[:\s]+(NIPT\s+\w+)',
            r'(NIPT\s+(?:Basic|Standard|Plus|Pro|Extended|Expanded))',
            r'(?:Panorama|Harmony|MaterniT21|verifi|NIFTY|Natera)',  # Common brand names
        ]
        for pattern in panel_patterns:
            panel_match = re.search(pattern, text, re.IGNORECASE)
            if panel_match:
                panel = panel_match.group(1).strip()
                # Normalize panel name
                if any(kw in panel.lower() for kw in ['expanded', 'extended', 'plus', 'comprehensive']):
                    data['panel'] = 'NIPT Plus'
                elif any(kw in panel.lower() for kw in ['pro', 'genome', 'full']):
                    data['panel'] = 'NIPT Pro'
                elif 'basic' in panel.lower():
                    data['panel'] = 'NIPT Basic'
                else:
                    data['panel'] = 'NIPT Standard'
                break

        # Extract sequencing reads
        reads_patterns = [
            r'(?:Total\s+)?Reads?[:\s]+(\d+\.?\d*)\s*(?:M|million)',
            r'(?:Sequencing\s+)?Reads?[:\s]+(\d+\.?\d*)',
            r'(\d+\.?\d*)\s*(?:M|million)\s+reads?',
        ]
        for pattern in reads_patterns:
            reads_match = re.search(pattern, text, re.IGNORECASE)
            if reads_match:
                reads = float(reads_match.group(1))
                if reads > 100:  # Likely in raw number, convert to millions
                    reads = reads / 1000000
                if 0.1 <= reads <= 100:  # Reasonable range
                    data['reads'] = round(reads, 2)
                    break

        # Extract fetal fraction (Cff)
        cff_patterns = [
            r'(?:Cff|FF|Fetal\s+Fraction|cfDNA\s+Fraction)[:\s]+(\d+\.?\d*)\s*%?',
            r'Fetal\s+(?:DNA\s+)?Fraction[:\s]+(\d+\.?\d*)',
            r'(\d+\.?\d*)\s*%?\s*(?:fetal\s+fraction|FF)',
        ]
        for pattern in cff_patterns:
            cff_match = re.search(pattern, text, re.IGNORECASE)
            if cff_match:
                cff = float(cff_match.group(1))
                if 0.5 <= cff <= 50:  # Reasonable fetal fraction range
                    data['cff'] = round(cff, 2)
                    break

        # Extract GC content
        gc_patterns = [
            r'GC\s*(?:Content)?[:\s]+(\d+\.?\d*)\s*%?',
            r'GC%[:\s]+(\d+\.?\d*)',
        ]
        for pattern in gc_patterns:
            gc_match = re.search(pattern, text, re.IGNORECASE)
            if gc_match:
                gc = float(gc_match.group(1))
                if 20 <= gc <= 80:  # Reasonable GC content range
                    data['gc'] = round(gc, 2)
                    break

        # Extract quality score
        qs_patterns = [
            r'QS[:\s]+(\d+\.?\d*)',
            r'Quality\s+Score[:\s]+(\d+\.?\d*)',
            r'(?:Data\s+)?Quality[:\s]+(\d+\.?\d*)',
        ]
        for pattern in qs_patterns:
            qs_match = re.search(pattern, text, re.IGNORECASE)
            if qs_match:
                qs = float(qs_match.group(1))
                if 0 <= qs <= 10:  # Reasonable QS range
                    data['qs'] = round(qs, 3)
                    break

        # Extract unique read rate
        unique_patterns = [
            r'Unique\s*(?:Read)?\s*(?:Rate)?[:\s]+(\d+\.?\d*)\s*%?',
            r'Uniquely\s+Mapped[:\s]+(\d+\.?\d*)',
            r'Mapping\s+Rate[:\s]+(\d+\.?\d*)',
        ]
        for pattern in unique_patterns:
            unique_match = re.search(pattern, text, re.IGNORECASE)
            if unique_match:
                unique = float(unique_match.group(1))
                if 0 <= unique <= 100:
                    data['unique_rate'] = round(unique, 2)
                    break

        # Extract error rate
        error_patterns = [
            r'Error\s*(?:Rate)?[:\s]+(\d+\.?\d*)\s*%?',
            r'Sequencing\s+Error[:\s]+(\d+\.?\d*)',
        ]
        for pattern in error_patterns:
            error_match = re.search(pattern, text, re.IGNORECASE)
            if error_match:
                error = float(error_match.group(1))
                if 0 <= error <= 10:
                    data['error_rate'] = round(error, 3)
                    break

        # ===== Z-SCORES (ALL AUTOSOMES) =====
        # Extract Z-scores for main trisomies (13, 18, 21)
        for chrom in [13, 18, 21]:
            z_patterns = [
                rf'(?:Z[-\s]?{chrom}|Chr(?:omosome)?\s*{chrom}\s*Z)[:\s]+(-?\d+\.?\d*)',
                rf'Trisomy\s+{chrom}.*?Z[-\s]?(?:Score)?[:\s]+(-?\d+\.?\d*)',
                rf'T{chrom}.*?Z[:\s]+(-?\d+\.?\d*)',
                rf'Chr(?:omosome)?\s*{chrom}[:\s]+.*?Z[:\s]+(-?\d+\.?\d*)',
                rf'Z[-\s]?Score.*?{chrom}[:\s]+(-?\d+\.?\d*)',
            ]
            for pattern in z_patterns:
                z_match = re.search(pattern, text, re.IGNORECASE)
                if z_match:
                    z_val = float(z_match.group(1))
                    if -20 <= z_val <= 50:  # Reasonable Z-score range
                        data['z_scores'][chrom] = round(z_val, 3)
                        break

        # Extract Z-scores for ALL other autosomes (1-22, excluding 13, 18, 21)
        for chrom in range(1, 23):
            if chrom in [13, 18, 21]:
                continue  # Already captured above

            z_patterns = [
                rf'(?:Z[-\s]?{chrom}|Chr(?:omosome)?\s*{chrom}\s*Z)[:\s]+(-?\d+\.?\d*)',
                rf'Chromosome\s+{chrom}.*?Z[:\s]+(-?\d+\.?\d*)',
                rf'Chr\s*{chrom}[:\s]+.*?(-?\d+\.?\d*)',
            ]
            for pattern in z_patterns:
                z_match = re.search(pattern, text, re.IGNORECASE)
                if z_match:
                    z_val = float(z_match.group(1))
                    if -20 <= z_val <= 50:
                        data['z_scores'][chrom] = round(z_val, 3)
                        break

        # Extract SCA Z-scores (XX and XY)
        z_xx_patterns = [
            r'Z[-\s]?XX[:\s]+(-?\d+\.?\d*)',
            r'XX\s+Z[-\s]?Score[:\s]+(-?\d+\.?\d*)',
            r'X[:\s]+.*?Z[:\s]+(-?\d+\.?\d*)',
        ]
        for pattern in z_xx_patterns:
            z_xx_match = re.search(pattern, text, re.IGNORECASE)
            if z_xx_match:
                z_val = float(z_xx_match.group(1))
                if -20 <= z_val <= 50:
                    data['z_scores']['XX'] = round(z_val, 3)
                    break

        z_xy_patterns = [
            r'Z[-\s]?XY[:\s]+(-?\d+\.?\d*)',
            r'XY\s+Z[-\s]?Score[:\s]+(-?\d+\.?\d*)',
            r'Y[:\s]+.*?Z[:\s]+(-?\d+\.?\d*)',
        ]
        for pattern in z_xy_patterns:
            z_xy_match = re.search(pattern, text, re.IGNORECASE)
            if z_xy_match:
                z_val = float(z_xy_match.group(1))
                if -20 <= z_val <= 50:
                    data['z_scores']['XY'] = round(z_val, 3)
                    break

        # ===== SCA TYPE & FETAL SEX DETECTION =====
        sca_patterns = [
            (r'Turner|Monosomy\s+X|45[,\s]*X(?:O)?', 'XO'),
            (r'Triple\s+X|Trisomy\s+X|47[,\s]*XXX', 'XXX'),
            (r'Klinefelter|47[,\s]*XXY', 'XXY'),
            (r'47[,\s]*XYY|Jacob(?:s)?(?:\s+syndrome)?', 'XYY'),
            (r'(?:Fetal\s+)?Sex[:\s]+Male|(?:Fetal\s+)?Gender[:\s]+Male|XY\s+(?:Male|detected)|Y\s+chromosome\s+(?:detected|present)', 'XY'),
            (r'(?:Fetal\s+)?Sex[:\s]+Female|(?:Fetal\s+)?Gender[:\s]+Female|XX\s+(?:Female|detected)|No\s+Y\s+chromosome', 'XX'),
        ]
        for pattern, sca_type in sca_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                data['sca_type'] = sca_type
                # Also set fetal sex based on SCA type
                if sca_type in ['XY', 'XXY', 'XYY']:
                    data['fetal_sex'] = 'Male'
                elif sca_type in ['XX', 'XO', 'XXX']:
                    data['fetal_sex'] = 'Female'
                break

        # Try to extract fetal sex separately if not determined
        if not data['fetal_sex']:
            sex_patterns = [
                (r'(?:Fetal\s+)?Sex[:\s]+Male|(?:Male|Boy)\s+fetus', 'Male'),
                (r'(?:Fetal\s+)?Sex[:\s]+Female|(?:Female|Girl)\s+fetus', 'Female'),
                (r'Y\s+chromosome\s+(?:detected|present|positive)', 'Male'),
                (r'Y\s+chromosome\s+(?:not\s+detected|absent|negative)', 'Female'),
            ]
            for pattern, sex in sex_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    data['fetal_sex'] = sex
                    break

        # ===== CNV FINDINGS =====
        # Look for CNV sections with more comprehensive patterns
        cnv_section_patterns = [
            r'CNV[:\s]+(.+?)(?:RAT|Rare|Final|Interpretation|Result|$)',
            r'Copy\s+Number\s+Variation[:\s]+(.+?)(?:RAT|Final|$)',
            r'Microdeletion/Microduplication[:\s]+(.+?)(?:Final|$)',
        ]
        for section_pattern in cnv_section_patterns:
            cnv_section = re.search(section_pattern, text, re.IGNORECASE | re.DOTALL)
            if cnv_section:
                cnv_text = cnv_section.group(1)

                # Extract CNV entries with various formats
                cnv_entry_patterns = [
                    r'(\d+\.?\d*)\s*(?:Mb|MB|megabases?).*?(\d+\.?\d*)\s*%',
                    r'(?:Size|Region)[:\s]+(\d+\.?\d*)\s*(?:Mb|MB).*?(?:Ratio|Score)[:\s]+(\d+\.?\d*)',
                    r'Chr(?:omosome)?\s*(\d+)[pq]?\d*.*?(\d+\.?\d*)\s*(?:Mb|MB)',
                ]
                for pattern in cnv_entry_patterns:
                    cnv_matches = re.finditer(pattern, cnv_text, re.IGNORECASE)
                    for match in cnv_matches:
                        try:
                            size = float(match.group(1))
                            ratio = float(match.group(2)) if match.lastindex >= 2 else 0
                            if 0.1 <= size <= 200:  # Reasonable CNV size
                                data['cnv_findings'].append({
                                    'size': round(size, 2),
                                    'ratio': round(ratio, 2)
                                })
                        except (ValueError, IndexError):
                            continue
                break

        # ===== RAT FINDINGS =====
        # Look for RAT/Rare Autosome sections
        rat_section_patterns = [
            r'(?:RAT|Rare\s+Auto(?:somal)?\s+Trisomy)[:\s]+(.+?)(?:Final|CNV|Interpretation|$)',
            r'Other\s+(?:Chromosomal|Autosomal)\s+Findings[:\s]+(.+?)(?:Final|$)',
        ]
        for section_pattern in rat_section_patterns:
            rat_section = re.search(section_pattern, text, re.IGNORECASE | re.DOTALL)
            if rat_section:
                rat_text = rat_section.group(1)

                # Extract RAT entries
                rat_entry_patterns = [
                    r'Chr(?:omosome)?\s*(\d+).*?Z[-\s]?(?:Score)?[:\s]+(-?\d+\.?\d*)',
                    r'Trisomy\s+(\d+).*?Z[:\s]+(-?\d+\.?\d*)',
                ]
                for pattern in rat_entry_patterns:
                    rat_matches = re.finditer(pattern, rat_text, re.IGNORECASE)
                    for match in rat_matches:
                        try:
                            chrom = int(match.group(1))
                            z_score = float(match.group(2))
                            if chrom not in [13, 18, 21] and 1 <= chrom <= 22:
                                data['rat_findings'].append({
                                    'chr': chrom,
                                    'z': round(z_score, 3)
                                })
                        except (ValueError, IndexError):
                            continue
                break

        # ===== MICRODELETION SYNDROMES =====
        microdeletion_patterns = [
            (r'22q11\.?2\s+(?:deletion|DiGeorge)', '22q11.2 Deletion (DiGeorge)'),
            (r'1p36\s+deletion', '1p36 Deletion'),
            (r'5p[-\s]?(?:deletion)?|Cri[- ]du[- ]Chat', '5p Deletion (Cri-du-Chat)'),
            (r'15q11\.?2\s+(?:deletion)?|Prader[- ]Willi|Angelman', '15q11.2 Deletion (Prader-Willi/Angelman)'),
            (r'4p[-\s]?(?:deletion)?|Wolf[- ]Hirschhorn', '4p Deletion (Wolf-Hirschhorn)'),
        ]
        for pattern, syndrome in microdeletion_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                # Check if positive or negative
                context = re.search(rf'{pattern}.{{0,100}}(positive|negative|detected|not\s+detected|high\s+risk|low\s+risk)',
                                   text, re.IGNORECASE)
                if context:
                    result = context.group(1).lower()
                    is_positive = result in ['positive', 'detected', 'high risk']
                    data['microdeletion_results'].append({
                        'syndrome': syndrome,
                        'result': 'Positive' if is_positive else 'Negative'
                    })

        # ===== QC STATUS & RESULTS =====
        qc_patterns = [
            r'QC\s+Status[:\s]+(\w+)',
            r'Quality\s+Control[:\s]+(\w+)',
            r'(?:Sample\s+)?Quality[:\s]+(PASS|FAIL|WARNING|ADEQUATE|INADEQUATE)',
        ]
        for pattern in qc_patterns:
            qc_match = re.search(pattern, text, re.IGNORECASE)
            if qc_match:
                qc_val = qc_match.group(1).upper()
                if qc_val in ['PASS', 'PASSED', 'ADEQUATE', 'ACCEPTABLE']:
                    data['qc_status'] = 'PASS'
                elif qc_val in ['FAIL', 'FAILED', 'INADEQUATE', 'REJECTED']:
                    data['qc_status'] = 'FAIL'
                else:
                    data['qc_status'] = 'WARNING'
                break

        # Extract final result/interpretation
        result_patterns = [
            r'(?:Final\s+)?(?:Interpretation|Result|Conclusion)[:\s]+([A-Za-z\s\(\)\-]+?)(?:\.|$|\n)',
            r'(?:Overall\s+)?(?:Risk|Assessment)[:\s]+((?:Low|High|Positive|Negative)[A-Za-z\s\(\)]*)',
            r'NIPT\s+Result[:\s]+([A-Za-z\s\(\)]+)',
        ]
        for pattern in result_patterns:
            result_match = re.search(pattern, text, re.IGNORECASE)
            if result_match:
                result = result_match.group(1).strip()
                if len(result) > 3:
                    data['final_result'] = result[:200]
                    break

        # Extract risk values if available
        risk_patterns = [
            (r'(?:T21|Trisomy\s*21|Down).*?Risk[:\s]+(?:1\s*(?:in|:)\s*)?(\d+)', 'risk_t21'),
            (r'(?:T18|Trisomy\s*18|Edwards).*?Risk[:\s]+(?:1\s*(?:in|:)\s*)?(\d+)', 'risk_t18'),
            (r'(?:T13|Trisomy\s*13|Patau).*?Risk[:\s]+(?:1\s*(?:in|:)\s*)?(\d+)', 'risk_t13'),
        ]
        for pattern, field in risk_patterns:
            risk_match = re.search(pattern, text, re.IGNORECASE)
            if risk_match:
                data[field] = f"1 in {risk_match.group(1)}"

        # Extract clinical notes
        notes_patterns = [
            r'(?:Clinical\s+)?Notes?[:\s]+(.+?)(?:\n\n|={3,}|Disclaimer|Limitation|$)',
            r'Comments?[:\s]+(.+?)(?:\n\n|={3,}|$)',
            r'(?:Additional\s+)?(?:Information|Remarks)[:\s]+(.+?)(?:\n\n|$)',
        ]
        for pattern in notes_patterns:
            notes_match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if notes_match:
                notes = notes_match.group(1).strip()
                # Clean up notes
                notes = re.sub(r'\s+', ' ', notes)
                if len(notes) > 5:
                    data['notes'] = notes[:500]
                    break

        # ===== EXTRACTION CONFIDENCE =====
        # Calculate confidence based on how much data was extracted
        extracted_fields = sum([
            bool(data['patient_name']),
            bool(data['mrn']),
            data['age'] > 0,
            data['weeks'] > 0,
            data['cff'] > 0,
            len(data['z_scores']) >= 3,
            bool(data['final_result']),
        ])

        if extracted_fields >= 6:
            data['extraction_confidence'] = 'HIGH'
        elif extracted_fields >= 4:
            data['extraction_confidence'] = 'MEDIUM'
        else:
            data['extraction_confidence'] = 'LOW'

        return data

    except Exception as e:
        st.error(f"PDF extraction error in {filename}: {str(e)}")
        return None

def parse_pdf_batch(pdf_files: List) -> Dict[str, List[Dict]]:
    """Parse multiple PDF files and group by patient MRN."""
    # Dictionary to group by MRN
    patients = {}
    errors = []
    
    for pdf_file in pdf_files:
        filename = pdf_file.name if hasattr(pdf_file, 'name') else 'unknown.pdf'
        data = extract_data_from_pdf(pdf_file, filename)
        
        if data:
            if data['mrn']:
                # Group by MRN
                mrn = data['mrn']
                if mrn not in patients:
                    patients[mrn] = []
                patients[mrn].append(data)
            else:
                errors.append(f"No MRN found in {filename}")
        else:
            errors.append(f"Failed to extract data from {filename}")
    
    return {'patients': patients, 'errors': errors}

def get_maternal_age_risk(age: int) -> Dict[str, float]:
    """Calculate maternal age-based prior risk for common aneuploidies.
    Based on published maternal age-specific risk data."""
    # Prior risks per 1000 pregnancies based on maternal age
    # Data from Hook EB, 1981 and updated studies
    age_risk_table = {
        20: {'T21': 1/1441, 'T18': 1/10000, 'T13': 1/14300},
        25: {'T21': 1/1383, 'T18': 1/8300, 'T13': 1/12500},
        30: {'T21': 1/959, 'T18': 1/5900, 'T13': 1/9100},
        32: {'T21': 1/659, 'T18': 1/4500, 'T13': 1/7100},
        34: {'T21': 1/446, 'T18': 1/3300, 'T13': 1/5200},
        35: {'T21': 1/356, 'T18': 1/2700, 'T13': 1/4200},
        36: {'T21': 1/280, 'T18': 1/2200, 'T13': 1/3400},
        37: {'T21': 1/218, 'T18': 1/1800, 'T13': 1/2700},
        38: {'T21': 1/167, 'T18': 1/1400, 'T13': 1/2100},
        39: {'T21': 1/128, 'T18': 1/1100, 'T13': 1/1700},
        40: {'T21': 1/97, 'T18': 1/860, 'T13': 1/1300},
        41: {'T21': 1/73, 'T18': 1/670, 'T13': 1/1000},
        42: {'T21': 1/55, 'T18': 1/530, 'T13': 1/800},
        43: {'T21': 1/41, 'T18': 1/410, 'T13': 1/630},
        44: {'T21': 1/30, 'T18': 1/320, 'T13': 1/490},
        45: {'T21': 1/23, 'T18': 1/250, 'T13': 1/380},
    }

    # Find closest age bracket
    if age < 20:
        return age_risk_table[20]
    elif age >= 45:
        return age_risk_table[45]

    # Linear interpolation for ages between table values
    sorted_ages = sorted(age_risk_table.keys())
    for i, table_age in enumerate(sorted_ages):
        if age <= table_age:
            if age == table_age:
                return age_risk_table[table_age]
            # Interpolate
            prev_age = sorted_ages[i-1] if i > 0 else table_age
            next_age = table_age
            ratio = (age - prev_age) / (next_age - prev_age) if next_age != prev_age else 0
            prev_risks = age_risk_table.get(prev_age, age_risk_table[20])
            next_risks = age_risk_table.get(next_age, age_risk_table[45])
            return {
                'T21': prev_risks['T21'] + (next_risks['T21'] - prev_risks['T21']) * ratio,
                'T18': prev_risks['T18'] + (next_risks['T18'] - prev_risks['T18']) * ratio,
                'T13': prev_risks['T13'] + (next_risks['T13'] - prev_risks['T13']) * ratio,
            }

    return age_risk_table[45]


def get_clinical_recommendation(result: str, test_type: str) -> str:
    """Generate clinical recommendation based on test result."""
    recommendations = {
        'POSITIVE': {
            'T21': "Confirmatory diagnostic testing (amniocentesis or CVS) is strongly recommended. Genetic counseling should be offered.",
            'T18': "Confirmatory diagnostic testing (amniocentesis or CVS) is strongly recommended. Detailed ultrasound and genetic counseling advised.",
            'T13': "Confirmatory diagnostic testing (amniocentesis or CVS) is strongly recommended. Detailed ultrasound and genetic counseling advised.",
            'SCA': "Genetic counseling recommended. Confirmatory testing may be considered based on clinical judgment.",
            'CNV': "Detailed ultrasound recommended. Genetic counseling and possible confirmatory testing advised.",
            'RAT': "Genetic counseling recommended. Clinical correlation and possible confirmatory testing advised."
        },
        'HIGH': {
            'default': "Re-analysis recommended. If persistent, consider confirmatory diagnostic testing."
        },
        'LOW': {
            'default': "No additional testing indicated based on NIPT result alone. Standard prenatal care recommended."
        }
    }

    if 'POSITIVE' in result.upper():
        return recommendations['POSITIVE'].get(test_type, recommendations['POSITIVE'].get('default', ''))
    elif 'HIGH' in result.upper() or 'AMBIGUOUS' in result.upper():
        return recommendations['HIGH']['default']
    else:
        return recommendations['LOW']['default']


def generate_pdf_report(report_id: int) -> Optional[bytes]:
    """Generate comprehensive clinical PDF report for pathologist review."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            query = """
                SELECT r.id, p.full_name, p.mrn_id, p.age, p.weeks, r.created_at, p.clinical_notes,
                       r.panel_type, r.qc_status, r.qc_details, r.qc_advice, r.qc_metrics_json,
                       r.t21_res, r.t18_res, r.t13_res, r.sca_res,
                       r.cnv_json, r.rat_json, r.full_z_json, r.final_summary,
                       p.weight_kg, p.height_cm, p.bmi,
                       u.full_name as technician_name
                FROM results r
                JOIN patients p ON p.id = r.patient_id
                LEFT JOIN users u ON u.id = r.created_by
                WHERE r.id = ?
            """
            df = pd.read_sql(query, conn, params=(report_id,))

        if df.empty: return None

        row = df.iloc[0]
        cnvs = json.loads(row['cnv_json']) if row['cnv_json'] else []
        rats = json.loads(row['rat_json']) if row['rat_json'] else []
        z_data = json.loads(row['full_z_json']) if row['full_z_json'] else {}
        qc_details = row['qc_details'] if row['qc_details'] else "[]"
        qc_metrics = json.loads(row['qc_metrics_json']) if row.get('qc_metrics_json') else {}
        config = load_config()

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.4*inch, bottomMargin=0.5*inch)
        story = []
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=16,
                                     textColor=colors.HexColor('#1a5276'), alignment=TA_CENTER,
                                     spaceAfter=6)
        subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=10,
                                        alignment=TA_CENTER, textColor=colors.HexColor('#566573'))
        section_style = ParagraphStyle('Section', parent=styles['Heading2'], fontSize=11,
                                       textColor=colors.HexColor('#2c3e50'), spaceBefore=10, spaceAfter=4)
        small_style = ParagraphStyle('Small', parent=styles['Normal'], fontSize=8,
                                     textColor=colors.HexColor('#7f8c8d'))
        warning_style = ParagraphStyle('Warning', parent=styles['Normal'], fontSize=9,
                                       textColor=colors.HexColor('#c0392b'), fontName='Helvetica-Bold')
        # Cell style for wrapped text in tables
        cell_style = ParagraphStyle('Cell', parent=styles['Normal'], fontSize=8,
                                    leading=10, wordWrap='CJK')
        cell_style_bold = ParagraphStyle('CellBold', parent=styles['Normal'], fontSize=8,
                                         leading=10, wordWrap='CJK', fontName='Helvetica-Bold')

        # ===== HEADER =====
        story.append(Paragraph("CLINICAL GENETICS LABORATORY", title_style))
        story.append(Paragraph("Non-Invasive Prenatal Testing (NIPT) Report", subtitle_style))
        story.append(Spacer(1, 0.15*inch))

        # ===== REPORT METADATA =====
        report_date = row['created_at'][:10] if row['created_at'] else datetime.now().strftime('%Y-%m-%d')
        report_time = row['created_at'][11:19] if len(row['created_at']) > 10 else ''

        meta_data = [
            ['Report ID:', str(row['id']), 'Report Date:', report_date],
            ['Panel Type:', row['panel_type'], 'Report Time:', report_time],
        ]
        meta_table = Table(meta_data, colWidths=[1.1*inch, 2.2*inch, 1.1*inch, 2.1*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2c3e50')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.1*inch))

        # ===== PATIENT INFORMATION =====
        story.append(Paragraph("PATIENT INFORMATION", section_style))

        # Calculate BMI if not present
        bmi_val = row['bmi'] if row['bmi'] else (
            round(row['weight_kg'] / ((row['height_cm']/100)**2), 1)
            if row['weight_kg'] and row['height_cm'] and row['height_cm'] > 0 else 'N/A'
        )

        # Get maternal age risk
        maternal_risk = get_maternal_age_risk(int(row['age'])) if row['age'] else {}

        patient_data = [
            ['Name:', str(row['full_name']), 'MRN:', str(row['mrn_id'])],
            ['Maternal Age:', f"{row['age']} years", 'Gestational Age:', f"{row['weeks']} weeks"],
            ['Weight:', f"{row['weight_kg']} kg" if row['weight_kg'] else 'N/A',
             'Height:', f"{row['height_cm']} cm" if row['height_cm'] else 'N/A'],
            ['BMI:', str(bmi_val), '', ''],
        ]
        patient_table = Table(patient_data, colWidths=[1.1*inch, 2.2*inch, 1.1*inch, 2.1*inch])
        patient_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ]))
        story.append(patient_table)
        story.append(Spacer(1, 0.1*inch))

        # ===== QUALITY CONTROL METRICS =====
        story.append(Paragraph("QUALITY CONTROL ASSESSMENT", section_style))

        qc_status = row['qc_status'] or 'N/A'
        qc_color = colors.HexColor('#27ae60') if qc_status == 'PASS' else (
            colors.HexColor('#f39c12') if qc_status == 'WARNING' else colors.HexColor('#e74c3c'))

        qc_header = [['QC Status', 'Parameter', 'Value', 'Reference Range', 'Status']]
        qc_rows = []

        # Get thresholds from config
        thresholds = config['QC_THRESHOLDS']
        panel_limits = config['PANEL_READ_LIMITS']
        min_reads = panel_limits.get(row['panel_type'], 5)

        # Helper function to determine individual metric status
        def get_metric_status(param, value, ref_check):
            if value == 'N/A' or value is None:
                return 'N/A'
            try:
                return 'PASS' if ref_check(float(value)) else 'FAIL'
            except (ValueError, TypeError):
                return 'N/A'

        # Get actual values from qc_metrics
        cff_val = qc_metrics.get('cff', 'N/A')
        gc_val = qc_metrics.get('gc', 'N/A')
        reads_val = qc_metrics.get('reads', 'N/A')
        uniq_val = qc_metrics.get('unique_rate', 'N/A')
        error_val = qc_metrics.get('error_rate', 'N/A')
        qs_val = qc_metrics.get('qs', 'N/A')

        # Format values with units
        cff_display = f"{cff_val}%" if cff_val != 'N/A' else 'N/A'
        gc_display = f"{gc_val}%" if gc_val != 'N/A' else 'N/A'
        reads_display = f"{reads_val}M" if reads_val != 'N/A' else 'N/A'
        uniq_display = f"{uniq_val}%" if uniq_val != 'N/A' else 'N/A'
        error_display = f"{error_val}%" if error_val != 'N/A' else 'N/A'
        qs_display = str(qs_val) if qs_val != 'N/A' else 'N/A'

        # Determine status for each metric
        cff_status = get_metric_status('cff', cff_val, lambda v: v >= thresholds['MIN_CFF'])
        gc_status = get_metric_status('gc', gc_val, lambda v: thresholds['GC_RANGE'][0] <= v <= thresholds['GC_RANGE'][1])
        reads_status = get_metric_status('reads', reads_val, lambda v: v >= min_reads)
        uniq_status = get_metric_status('uniq', uniq_val, lambda v: v >= thresholds['MIN_UNIQ_RATE'])
        error_status = get_metric_status('error', error_val, lambda v: v <= thresholds['MAX_ERROR_RATE'])
        qs_status = get_metric_status('qs', qs_val, lambda v: v < thresholds['QS_LIMIT_NEG'])

        # Build QC items with actual values
        qc_items = [
            ('Fetal Fraction (Cff)', cff_display, f"≥ {thresholds['MIN_CFF']}%", cff_status),
            ('GC Content', gc_display, f"{thresholds['GC_RANGE'][0]}-{thresholds['GC_RANGE'][1]}%", gc_status),
            ('Sequencing Reads', reads_display, f"≥ {min_reads}M", reads_status),
            ('Unique Read Rate', uniq_display, f"≥ {thresholds['MIN_UNIQ_RATE']}%", uniq_status),
            ('Error Rate', error_display, f"≤ {thresholds['MAX_ERROR_RATE']}%", error_status),
            ('Quality Score', qs_display, f"< {thresholds['QS_LIMIT_NEG']}", qs_status),
        ]

        for i, (param, val, ref, status) in enumerate(qc_items):
            if i == 0:
                qc_rows.append([qc_status, param, val, ref, status])
            else:
                qc_rows.append(['', param, val, ref, status])

        qc_table_data = qc_header + qc_rows
        qc_table = Table(qc_table_data, colWidths=[0.9*inch, 1.5*inch, 0.9*inch, 1.5*inch, 1.0*inch])

        # Build table style with color-coded status cells
        table_style_list = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
            ('BACKGROUND', (0, 1), (0, 1), qc_color),
            ('TEXTCOLOR', (0, 1), (0, 1), colors.whitesmoke),
            ('FONTNAME', (0, 1), (0, 1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]

        # Color code the status column based on PASS/FAIL
        for row_idx, (_, _, _, status) in enumerate(qc_items):
            if status == 'PASS':
                table_style_list.append(('BACKGROUND', (4, row_idx + 1), (4, row_idx + 1), colors.HexColor('#d4edda')))
                table_style_list.append(('TEXTCOLOR', (4, row_idx + 1), (4, row_idx + 1), colors.HexColor('#155724')))
            elif status == 'FAIL':
                table_style_list.append(('BACKGROUND', (4, row_idx + 1), (4, row_idx + 1), colors.HexColor('#f8d7da')))
                table_style_list.append(('TEXTCOLOR', (4, row_idx + 1), (4, row_idx + 1), colors.HexColor('#721c24')))

        qc_table.setStyle(TableStyle(table_style_list))
        story.append(qc_table)

        if row['qc_advice'] and row['qc_advice'] != 'None':
            story.append(Spacer(1, 0.05*inch))
            story.append(Paragraph(f"<b>QC Recommendation:</b> {row['qc_advice']}", warning_style))

        story.append(Spacer(1, 0.1*inch))

        # ===== MAIN RESULTS =====
        story.append(Paragraph("ANEUPLOIDY SCREENING RESULTS", section_style))

        # Determine fetal sex from SCA result
        sca_result = row['sca_res'] or ''
        fetal_sex = 'Male' if 'Male' in sca_result or 'XY' in sca_result else (
            'Female' if 'Female' in sca_result or 'XX' in sca_result else 'Undetermined')

        # Get Z-scores
        z21 = z_data.get('21', z_data.get(21, 'N/A'))
        z18 = z_data.get('18', z_data.get(18, 'N/A'))
        z13 = z_data.get('13', z_data.get(13, 'N/A'))
        z_xx = z_data.get('XX', 'N/A')
        z_xy = z_data.get('XY', 'N/A')

        # Helper to format Z-score
        def fmt_z(z):
            if isinstance(z, (int, float)):
                return f"{z:.2f}"
            return str(z)

        # Results table with risk interpretation - use Paragraph for text wrapping
        results_header = [[
            Paragraph('<b>Condition</b>', cell_style),
            Paragraph('<b>Result</b>', cell_style),
            Paragraph('<b>Z-Score</b>', cell_style),
            Paragraph('<b>Risk Category</b>', cell_style),
            Paragraph('<b>Ref</b>', cell_style)
        ]]
        results_rows = [
            [Paragraph('Trisomy 21 (Down Syndrome)', cell_style),
             Paragraph(str(row['t21_res']), cell_style),
             Paragraph(fmt_z(z21), cell_style),
             Paragraph('SCREEN POSITIVE' if 'POSITIVE' in str(row['t21_res']).upper() else 'LOW RISK', cell_style),
             Paragraph('Z &lt; 2.58', cell_style)],
            [Paragraph('Trisomy 18 (Edwards Syndrome)', cell_style),
             Paragraph(str(row['t18_res']), cell_style),
             Paragraph(fmt_z(z18), cell_style),
             Paragraph('SCREEN POSITIVE' if 'POSITIVE' in str(row['t18_res']).upper() else 'LOW RISK', cell_style),
             Paragraph('Z &lt; 2.58', cell_style)],
            [Paragraph('Trisomy 13 (Patau Syndrome)', cell_style),
             Paragraph(str(row['t13_res']), cell_style),
             Paragraph(fmt_z(z13), cell_style),
             Paragraph('SCREEN POSITIVE' if 'POSITIVE' in str(row['t13_res']).upper() else 'LOW RISK', cell_style),
             Paragraph('Z &lt; 2.58', cell_style)],
            [Paragraph('Sex Chromosome Aneuploidy', cell_style),
             Paragraph(str(row['sca_res']), cell_style),
             Paragraph(f"XX:{fmt_z(z_xx)} XY:{fmt_z(z_xy)}", cell_style),
             Paragraph('SCREEN POSITIVE' if 'POSITIVE' in str(row['sca_res']).upper() else 'LOW RISK', cell_style),
             Paragraph('Z &lt; 4.5', cell_style)],
        ]

        results_data = results_header + results_rows
        results_table = Table(results_data, colWidths=[1.6*inch, 1.6*inch, 1.0*inch, 1.2*inch, 0.8*inch])

        # Color code results
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]

        # Highlight positive results - check Paragraph content
        for idx in range(len(results_rows)):
            result_text = str(row['t21_res']) if idx == 0 else (
                str(row['t18_res']) if idx == 1 else (
                    str(row['t13_res']) if idx == 2 else str(row['sca_res'])
                )
            )
            if 'POSITIVE' in result_text.upper():
                table_style.append(('BACKGROUND', (0, idx+1), (-1, idx+1), colors.HexColor('#fadbd8')))

        results_table.setStyle(TableStyle(table_style))
        story.append(results_table)
        story.append(Spacer(1, 0.08*inch))

        # Fetal Sex
        story.append(Paragraph(f"<b>Fetal Sex:</b> {fetal_sex}", styles['Normal']))
        story.append(Spacer(1, 0.1*inch))

        # ===== CNV FINDINGS =====
        if cnvs and len(cnvs) > 0:
            story.append(Paragraph("COPY NUMBER VARIATION (CNV) FINDINGS", section_style))
            cnv_header = [[Paragraph('<b>Finding</b>', cell_style), Paragraph('<b>Clinical Significance</b>', cell_style)]]
            cnv_rows = [[Paragraph(str(cnv), cell_style), Paragraph(get_clinical_recommendation(str(cnv), 'CNV'), cell_style)] for cnv in cnvs]
            cnv_data = cnv_header + cnv_rows
            cnv_table = Table(cnv_data, colWidths=[2.5*inch, 4*inch])
            cnv_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#8e44ad')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(cnv_table)
            story.append(Spacer(1, 0.1*inch))

        # ===== RAT FINDINGS =====
        if rats and len(rats) > 0:
            story.append(Paragraph("RARE AUTOSOMAL TRISOMY (RAT) FINDINGS", section_style))
            rat_header = [[Paragraph('<b>Finding</b>', cell_style), Paragraph('<b>Clinical Significance</b>', cell_style)]]
            rat_rows = [[Paragraph(str(rat), cell_style), Paragraph(get_clinical_recommendation(str(rat), 'RAT'), cell_style)] for rat in rats]
            rat_data = rat_header + rat_rows
            rat_table = Table(rat_data, colWidths=[2.5*inch, 4*inch])
            rat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d35400')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(rat_table)
            story.append(Spacer(1, 0.1*inch))

        # ===== MATERNAL FACTORS & AGE-BASED RISK =====
        story.append(Paragraph("MATERNAL FACTORS & AGE-BASED RISK", section_style))

        # Build maternal factors text
        maternal_factors = []
        if row['age']:
            maternal_factors.append(f"<b>Maternal Age:</b> {row['age']} years")
        if bmi_val and bmi_val != 'N/A':
            bmi_category = ""
            try:
                bmi_num = float(bmi_val)
                if bmi_num < 18.5:
                    bmi_category = " (Underweight)"
                elif bmi_num < 25:
                    bmi_category = " (Normal)"
                elif bmi_num < 30:
                    bmi_category = " (Overweight)"
                else:
                    bmi_category = " (Obese - may affect fetal fraction)"
            except:
                pass
            maternal_factors.append(f"<b>BMI:</b> {bmi_val}{bmi_category}")
        if row['weeks']:
            maternal_factors.append(f"<b>Gestational Age:</b> {row['weeks']} weeks")

        if maternal_factors:
            story.append(Paragraph(" | ".join(maternal_factors), styles['Normal']))
            story.append(Spacer(1, 0.05*inch))

        # Age-based prior risk
        if maternal_risk and row['age']:
            risk_text = (f"Based on maternal age of {row['age']} years, the a priori risks are: "
                        f"Trisomy 21: 1 in {int(1/maternal_risk['T21'])}, "
                        f"Trisomy 18: 1 in {int(1/maternal_risk['T18'])}, "
                        f"Trisomy 13: 1 in {int(1/maternal_risk['T13'])}")
            story.append(Paragraph(risk_text, small_style))
        story.append(Spacer(1, 0.1*inch))

        # ===== FINAL INTERPRETATION =====
        story.append(Paragraph("FINAL INTERPRETATION", section_style))

        final_summary = row['final_summary']
        final_color = colors.HexColor('#27ae60') if 'NEGATIVE' in str(final_summary).upper() else (
            colors.HexColor('#e74c3c') if 'POSITIVE' in str(final_summary).upper() else colors.HexColor('#f39c12'))

        # Create centered style for final box with text wrapping
        final_cell_style = ParagraphStyle('FinalCell', parent=styles['Normal'], fontSize=12,
                                          leading=14, alignment=TA_CENTER, textColor=colors.whitesmoke,
                                          fontName='Helvetica-Bold', wordWrap='CJK')
        final_box = Table([[Paragraph(str(final_summary), final_cell_style)]], colWidths=[6.5*inch])
        final_box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), final_color),
            ('BOTTOMPADDING', (0, 0), (0, 0), 10),
            ('TOPPADDING', (0, 0), (0, 0), 10),
            ('LEFTPADDING', (0, 0), (0, 0), 10),
            ('RIGHTPADDING', (0, 0), (0, 0), 10),
        ]))
        story.append(final_box)
        story.append(Spacer(1, 0.1*inch))

        # ===== CLINICAL RECOMMENDATIONS =====
        story.append(Paragraph("CLINICAL RECOMMENDATIONS", section_style))

        recommendations = []
        if 'POSITIVE' in str(row['t21_res']).upper():
            recommendations.append(f"• Trisomy 21: {get_clinical_recommendation(row['t21_res'], 'T21')}")
        if 'POSITIVE' in str(row['t18_res']).upper():
            recommendations.append(f"• Trisomy 18: {get_clinical_recommendation(row['t18_res'], 'T18')}")
        if 'POSITIVE' in str(row['t13_res']).upper():
            recommendations.append(f"• Trisomy 13: {get_clinical_recommendation(row['t13_res'], 'T13')}")
        if 'POSITIVE' in str(row['sca_res']).upper():
            recommendations.append(f"• SCA: {get_clinical_recommendation(row['sca_res'], 'SCA')}")

        if not recommendations:
            recommendations.append("• No high-risk findings detected. Continue standard prenatal care.")
            recommendations.append("• NIPT is a screening test. It does not diagnose chromosomal abnormalities.")

        for rec in recommendations:
            story.append(Paragraph(rec, styles['Normal']))
        story.append(Spacer(1, 0.1*inch))

        # ===== CLINICAL NOTES =====
        if row['clinical_notes']:
            story.append(Paragraph("CLINICAL NOTES & OBSERVATIONS", section_style))
            notes_text = str(row['clinical_notes'])
            # Create a styled box for clinical notes
            notes_style = ParagraphStyle('Notes', parent=styles['Normal'], fontSize=9,
                                         leading=12, wordWrap='CJK', leftIndent=10, rightIndent=10)
            notes_box = Table([[Paragraph(notes_text, notes_style)]], colWidths=[6.5*inch])
            notes_box.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#f8f9fa')),
                ('BOX', (0, 0), (0, 0), 0.5, colors.HexColor('#dee2e6')),
                ('BOTTOMPADDING', (0, 0), (0, 0), 8),
                ('TOPPADDING', (0, 0), (0, 0), 8),
                ('LEFTPADDING', (0, 0), (0, 0), 8),
                ('RIGHTPADDING', (0, 0), (0, 0), 8),
            ]))
            story.append(notes_box)

            # Highlight key clinical markers if present
            key_markers = []
            notes_lower = notes_text.lower()
            if 'nuchal' in notes_lower or 'nt' in notes_lower:
                key_markers.append("Nuchal Translucency noted")
            if 'fetal fraction' in notes_lower or 'ff' in notes_lower:
                key_markers.append("Fetal Fraction concerns noted")
            if 'ivf' in notes_lower or 'icsi' in notes_lower:
                key_markers.append("ART/IVF conception noted")
            if 'twin' in notes_lower or 'multiple' in notes_lower:
                key_markers.append("Multiple gestation noted")

            if key_markers:
                story.append(Spacer(1, 0.05*inch))
                markers_text = "<i>Key clinical markers: " + ", ".join(key_markers) + "</i>"
                story.append(Paragraph(markers_text, small_style))

            story.append(Spacer(1, 0.1*inch))

        # ===== LIMITATIONS & DISCLAIMER =====
        story.append(Paragraph("LIMITATIONS AND DISCLAIMER", section_style))
        disclaimer_text = """
        <b>Important Information:</b><br/>
        • NIPT is a screening test, not a diagnostic test. Positive results should be confirmed with diagnostic testing (amniocentesis or CVS).<br/>
        • False positive and false negative results can occur. A negative result does not eliminate the possibility of chromosomal abnormalities.<br/>
        • This test screens for specific chromosomal conditions and does not detect all genetic disorders.<br/>
        • Results should be interpreted in conjunction with other clinical findings, ultrasound, and maternal history.<br/>
        • Test performance may be affected by factors including: low fetal fraction, maternal chromosomal abnormalities, confined placental mosaicism, vanishing twin, or maternal malignancy.<br/>
        • Genetic counseling is recommended for all patients, especially those with positive or inconclusive results.
        """
        story.append(Paragraph(disclaimer_text, small_style))
        story.append(Spacer(1, 0.15*inch))

        # ===== SIGNATURE SECTION =====
        story.append(Paragraph("AUTHORIZATION", section_style))

        sig_data = [
            ['Performed by:', row['technician_name'] or 'Laboratory Staff', 'Date:', report_date],
            ['', '', '', ''],
            ['Reviewed by:', '_' * 30, 'Date:', '_' * 15],
            ['Clinical Pathologist', '', '', ''],
            ['', '', '', ''],
            ['Approved by:', '_' * 30, 'Date:', '_' * 15],
            ['Laboratory Director', '', '', ''],
        ]
        sig_table = Table(sig_data, colWidths=[1.2*inch, 2.3*inch, 0.8*inch, 2.2*inch])
        sig_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('FONTSIZE', (0, 3), (0, 3), 8),
            ('FONTSIZE', (0, 6), (0, 6), 8),
            ('TEXTCOLOR', (0, 3), (0, 3), colors.HexColor('#7f8c8d')),
            ('TEXTCOLOR', (0, 6), (0, 6), colors.HexColor('#7f8c8d')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(sig_table)

        # ===== FOOTER =====
        story.append(Spacer(1, 0.2*inch))
        footer_text = f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | NRIS v2.0 Enhanced Edition"
        story.append(Paragraph(footer_text, small_style))

        doc.build(story)
        return buffer.getvalue()

    except Exception as e:
        st.error(f"PDF generation error: {e}")
        return None

# ==================== ANALYTICS ====================

def get_analytics_data() -> Dict:
    """Fetch analytics."""
    with sqlite3.connect(DB_FILE) as conn:
        total = pd.read_sql("SELECT COUNT(*) as count FROM results", conn).iloc[0]['count']
        qc_stats = pd.read_sql("SELECT qc_status, COUNT(*) as count FROM results GROUP BY qc_status", conn)
        outcomes = pd.read_sql("SELECT final_summary, COUNT(*) as count FROM results GROUP BY final_summary", conn)
        trisomies = pd.read_sql("""
            SELECT 
                SUM(CASE WHEN t21_res LIKE '%POSITIVE%' THEN 1 ELSE 0 END) as t21,
                SUM(CASE WHEN t18_res LIKE '%POSITIVE%' THEN 1 ELSE 0 END) as t18,
                SUM(CASE WHEN t13_res LIKE '%POSITIVE%' THEN 1 ELSE 0 END) as t13
            FROM results
        """, conn)
        recent = pd.read_sql("""
            SELECT DATE(r.created_at) as date, COUNT(*) as count 
            FROM results r 
            WHERE r.created_at >= date('now', '-30 days')
            GROUP BY DATE(r.created_at)
        """, conn)
        panels = pd.read_sql("SELECT panel_type, COUNT(*) as count FROM results GROUP BY panel_type", conn)
        
        return {'total': total, 'qc_stats': qc_stats, 'outcomes': outcomes,
                'trisomies': trisomies, 'recent': recent, 'panels': panels}

def render_analytics_dashboard():
    """Render analytics dashboard."""
    st.header("📊 Analytics Dashboard")
    
    data = get_analytics_data()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Tests", data['total'])
    with col2:
        pass_rate = (data['qc_stats'][data['qc_stats']['qc_status'] == 'PASS']['count'].sum() / data['total'] * 100) if data['total'] > 0 else 0
        st.metric("QC Pass Rate", f"{pass_rate:.1f}%")
    with col3:
        pos = data['outcomes'][data['outcomes']['final_summary'].str.contains('POSITIVE', na=False)]['count'].sum()
        st.metric("Positive", pos)
    with col4:
        fail = data['qc_stats'][data['qc_stats']['qc_status'] == 'FAIL']['count'].sum()
        st.metric("QC Fail", fail)
    
    st.divider()
    
    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("QC Distribution")
        if not data['qc_stats'].empty:
            fig = px.pie(data['qc_stats'], values='count', names='qc_status',
                        color_discrete_map={'PASS': '#2ECC71', 'FAIL': '#E74C3C', 'WARNING': '#F39C12'})
            st.plotly_chart(fig, use_container_width=True)
    
    with c2:
        st.subheader("Outcomes")
        if not data['outcomes'].empty:
            fig = px.bar(data['outcomes'], x='final_summary', y='count', text='count')
            st.plotly_chart(fig, use_container_width=True)
    
    c3, c4 = st.columns(2)
    
    with c3:
        st.subheader("Trisomy Detection")
        if not data['trisomies'].empty:
            tris_df = pd.DataFrame({
                'Type': ['T21', 'T18', 'T13'],
                'Count': [data['trisomies'].iloc[0]['t21'], 
                         data['trisomies'].iloc[0]['t18'],
                         data['trisomies'].iloc[0]['t13']]
            })
            fig = px.bar(tris_df, x='Type', y='Count', color='Type', text='Count')
            st.plotly_chart(fig, use_container_width=True)
    
    with c4:
        st.subheader("Panel Types")
        if not data['panels'].empty:
            fig = px.pie(data['panels'], values='count', names='panel_type')
            st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("Activity (30 Days)")
    if not data['recent'].empty:
        fig = px.line(data['recent'], x='date', y='count', markers=True)
        st.plotly_chart(fig, use_container_width=True)

# ==================== UI MAIN ====================

def render_login():
    """Login UI."""
    st.markdown("<h1 style='text-align: center;'>🧬 NRIS v2.0</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>NIPT Result Interpretation System</p>", unsafe_allow_html=True)
    
    username = st.text_input("Username", key="login_user")
    password = st.text_input("Password", type="password", key="login_pass")
    
    if st.button("🔐 Login", use_container_width=True, type="primary"):
        if username and password:
            user = authenticate_user(username, password)
            if user:
                st.session_state.user = user
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("❌ Invalid username or password")
        else:
            st.warning("⚠️ Please enter both username and password")
    
    st.divider()
    st.info("💡 Default credentials:\n- Username: **admin**\n- Password: **admin123**")

def main():
    st.set_page_config(page_title="NRIS v2.0", layout="wide", page_icon="🧬")
    init_database()
    
    # Session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'cnv_list' not in st.session_state:
        st.session_state.cnv_list = []
    if 'rat_list' not in st.session_state:
        st.session_state.rat_list = []
    if 'analysis_complete' not in st.session_state:
        st.session_state.analysis_complete = False
    if 'current_result' not in st.session_state:
        st.session_state.current_result = {}
    if 'last_report_id' not in st.session_state:
        st.session_state.last_report_id = None
    
    # Authentication check
    if not st.session_state.authenticated:
        render_login()
        return
    
    # Sidebar
    with st.sidebar:
        st.title(f"👤 {st.session_state.user['name']}")
        st.caption(f"Role: {st.session_state.user['role']}")
        
        if st.button("🚪 Logout"):
            st.session_state.authenticated = False
            st.rerun()
        
        st.divider()
        
        # Quick stats
        with sqlite3.connect(DB_FILE) as conn:
            total = pd.read_sql("SELECT COUNT(*) as c FROM results", conn).iloc[0]['c']
            today = pd.read_sql("SELECT COUNT(*) as c FROM results WHERE DATE(created_at) = DATE('now')", conn).iloc[0]['c']
        
        st.metric("Total Records", total)
        st.metric("Today", today)
    
    # Main tabs
    tabs = st.tabs(["🔬 Analysis", "📊 Registry", "📈 Analytics", "📂 Batch", "⚙️ Settings"])
    
    config = load_config()
    
    # TAB 1: ANALYSIS
    with tabs[0]:
        st.title("🧬 NIPT Analysis")
        
        with st.container():
            c1, c2, c3 = st.columns(3)
            p_name = c1.text_input("Patient Name")
            p_id = c2.text_input("MRN")
            p_age = c3.number_input("Age", 15, 60, 30)
            
            c4, c5, c6, c7 = st.columns(4)
            p_weight = c4.number_input("Weight (kg)", 0.0, 200.0, 65.0)
            p_height = c5.number_input("Height (cm)", 0, 250, 165)
            bmi = round(p_weight / ((p_height/100)**2), 2) if p_height > 0 else 0
            c6.metric("BMI", f"{bmi:.1f}" if bmi > 0 else "--")
            p_weeks = c7.number_input("Weeks", 0, 42, 12)
            p_notes = st.text_area("Notes", height=60)
        
        st.markdown("---")
        
        st.subheader("Sequencing Metrics")
        panel_type = st.selectbox("Panel", list(config['PANEL_READ_LIMITS'].keys()))
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        reads = m1.number_input("Reads (M)", 0.0, 100.0, 8.0)
        cff = m2.number_input("Cff %", 0.0, 50.0, 10.0)
        gc = m3.number_input("GC %", 0.0, 100.0, 40.0)
        qs = m4.number_input("QS", 0.0, 10.0, 1.0)
        uniq_rate = m5.number_input("Unique %", 0.0, 100.0, 75.0)
        error_rate = m6.number_input("Error %", 0.0, 5.0, 0.1)
        
        # Validation
        val_errors = validate_inputs(reads, cff, gc, p_age)
        if val_errors:
            for err in val_errors:
                st.error(err)
        
        st.markdown("---")
        
        c_tri, c_sca = st.columns(2)
        with c_tri:
            st.subheader("Trisomy Z-Scores")
            z21 = st.number_input("Z-21", -10.0, 50.0, 0.5)
            z18 = st.number_input("Z-18", -10.0, 50.0, 0.5)
            z13 = st.number_input("Z-13", -10.0, 50.0, 0.5)
        
        with c_sca:
            st.subheader("Sex Chromosomes")
            sca_type = st.selectbox("Type", ["XX", "XY", "XO", "XXX", "XXY", "XYY"])
            z1, z2 = st.columns(2)
            z_xx = z1.number_input("Z-XX", -10.0, 50.0, 0.0)
            z_xy = z2.number_input("Z-XY", -10.0, 50.0, 0.0)
        
        st.markdown("---")
        
        d1, d2 = st.columns(2)
        with d1:
            st.subheader("CNV Findings")
            with st.form("cnv_form"):
                sz = st.number_input("Size (Mb)", 0.0)
                rt = st.number_input("Ratio (%)", 0.0)
                if st.form_submit_button("Add CNV") and sz > 0:
                    st.session_state.cnv_list.append({"size": sz, "ratio": rt})
                    st.rerun()
            
            for i, item in enumerate(st.session_state.cnv_list):
                col_a, col_b = st.columns([4, 1])
                col_a.text(f"{i+1}. {item['size']}Mb | {item['ratio']}%")
                if col_b.button("❌", key=f"del_cnv_{i}"):
                    st.session_state.cnv_list.pop(i)
                    st.rerun()
        
        with d2:
            st.subheader("Rare Autosomes (RAT)")
            with st.form("rat_form"):
                r_chr = st.number_input("Chr #", 1, 22, 7)
                r_z = st.number_input("Z-Score", 0.0)
                if st.form_submit_button("Add RAT") and r_z > 0:
                    st.session_state.rat_list.append({"chr": r_chr, "z": r_z})
                    st.rerun()
            
            for i, item in enumerate(st.session_state.rat_list):
                col_a, col_b = st.columns([4, 1])
                col_a.text(f"{i+1}. Chr {item['chr']} | Z:{item['z']}")
                if col_b.button("❌", key=f"del_rat_{i}"):
                    st.session_state.rat_list.pop(i)
                    st.rerun()
        
        st.markdown("---")
        
        # Check for duplicate patient before save button
        if p_id:
            exists, existing_patient = check_duplicate_patient(p_id)
            if exists:
                st.warning(f"⚠️ Patient with ID '{p_id}' already exists in registry as '{existing_patient['name']}' "
                          f"(Age: {existing_patient['age']}, Results: {existing_patient['result_count']}). "
                          f"Saving will add a new result to this patient's record.")

        if st.button("💾 SAVE & ANALYZE", type="primary", disabled=bool(val_errors)):
            t21_res, t21_risk = analyze_trisomy(config, z21, "21")
            t18_res, t18_risk = analyze_trisomy(config, z18, "18")
            t13_res, t13_risk = analyze_trisomy(config, z13, "13")
            sca_res, sca_risk = analyze_sca(config, sca_type, z_xx, z_xy, cff)

            analyzed_cnvs = []
            is_cnv_high = False
            for item in st.session_state.cnv_list:
                msg, _, risk = analyze_cnv(item['size'], item['ratio'])
                if risk == "HIGH": is_cnv_high = True
                analyzed_cnvs.append(f"{item['size']}Mb ({item['ratio']}%) -> {msg}")

            analyzed_rats = []
            is_rat_high = False
            for item in st.session_state.rat_list:
                msg, risk = analyze_rat(config, item['chr'], item['z'])
                if risk in ["POSITIVE", "HIGH"]: is_rat_high = True
                analyzed_rats.append(f"Chr {item['chr']} (Z:{item['z']}) -> {msg}")

            all_risks = [t21_risk, t18_risk, t13_risk, sca_risk]
            is_positive = "POSITIVE" in all_risks
            is_high_risk = "HIGH" in all_risks or is_cnv_high or is_rat_high

            qc_stat, qc_msg, qc_advice = check_qc_metrics(
                config, panel_type, reads, cff, gc, qs, uniq_rate, error_rate, is_positive or is_high_risk
            )

            final_summary = "NEGATIVE"
            if is_positive: final_summary = "POSITIVE DETECTED"
            elif is_high_risk: final_summary = "HIGH RISK (SEE ADVICE)"
            if qc_stat == "FAIL": final_summary = "INVALID (QC FAIL)"

            p_data = {'name': p_name, 'id': p_id, 'age': p_age, 'weight': p_weight,
                      'height': p_height, 'bmi': bmi, 'weeks': p_weeks, 'notes': p_notes}
            r_data = {'panel': panel_type, 'qc_status': qc_stat, 'qc_msgs': qc_msg, 'qc_advice': qc_advice}
            c_data = {'t21': t21_res, 't18': t18_res, 't13': t13_res, 'sca': sca_res,
                      'cnv_list': analyzed_cnvs, 'rat_list': analyzed_rats, 'final': final_summary}

            full_z = {13: z13, 18: z18, 21: z21, 'XX': z_xx, 'XY': z_xy}
            for r in st.session_state.rat_list: full_z[r['chr']] = r['z']

            # Store QC metrics for PDF report
            qc_metrics = {
                'reads': reads,
                'cff': cff,
                'gc': gc,
                'qs': qs,
                'unique_rate': uniq_rate,
                'error_rate': error_rate
            }

            rid, msg = save_result(p_data, r_data, c_data, full_z, qc_metrics=qc_metrics)

            if rid:
                st.success("✅ Record Saved")
                st.session_state.last_report_id = rid
                st.session_state.current_result = {
                    'clinical': c_data,
                    'qc': {'status': qc_stat, 'msg': qc_msg, 'advice': qc_advice}
                }
                st.session_state.analysis_complete = True
                st.session_state.cnv_list = []
                st.session_state.rat_list = []
            else:
                st.error(f"Failed to save: {msg}")
        
        if st.session_state.analysis_complete:
            res = st.session_state.current_result['clinical']
            qc = st.session_state.current_result['qc']
            
            st.divider()
            
            if qc['status'] == "FAIL":
                st.error(f"❌ QC FAILED: {qc['msg']}")
                st.error(f"ACTION: {qc['advice']}")
            elif qc['status'] == "WARNING":
                st.warning(f"⚠️ QC WARNING: {qc['msg']}")
            else:
                st.success(f"✅ QC PASSED")

            rows = [
                ["Trisomy 21", res['t21']],
                ["Trisomy 18", res['t18']],
                ["Trisomy 13", res['t13']],
                ["Sex Chromosomes", res['sca']]
            ]
            for i in res['cnv_list']: rows.append(["CNV", i])
            for i in res['rat_list']: rows.append(["RAT", i])
            
            df_res = pd.DataFrame(rows, columns=["Test", "Result"])
            
            def color_rows(val):
                s = str(val)
                if "POSITIVE" in s: return 'background-color: #ffcccc; font-weight: bold'
                if "Re-library" in s or "Resample" in s: return 'background-color: #fff3cd'
                return ''
            
            st.dataframe(df_res.style.map(color_rows), use_container_width=True)
            st.info(f"📋 FINAL: {res['final']}")

            if st.session_state.last_report_id:
                col_a, col_b = st.columns(2)
                with col_a:
                    pdf_data = generate_pdf_report(st.session_state.last_report_id)
                    if pdf_data:
                        st.download_button("📄 Download PDF", pdf_data, 
                                         f"Report_{st.session_state.last_report_id}.pdf", "application/pdf")
                with col_b:
                    if st.button("🔄 New Analysis"):
                        st.session_state.analysis_complete = False
                        st.rerun()
    
    # TAB 2: REGISTRY
    with tabs[1]:
        st.header("📊 Patient Registry")
        
        col_search, col_refresh = st.columns([3, 1])
        with col_search:
            search_term = st.text_input("🔍 Search (Name/MRN)", "")
        with col_refresh:
            st.write("")
            st.write("")
            if st.button("🔄 Refresh"): st.rerun()

        with sqlite3.connect(DB_FILE) as conn:
            query = """
                SELECT r.id, r.created_at, p.full_name, p.mrn_id, r.panel_type, 
                       r.qc_status, r.final_summary 
                FROM results r 
                JOIN patients p ON p.id = r.patient_id 
                ORDER BY r.id DESC
            """
            df = pd.read_sql(query, conn)
        
        if not df.empty:
            if search_term:
                df = df[df['full_name'].str.contains(search_term, case=False, na=False) | 
                       df['mrn_id'].str.contains(search_term, case=False, na=False)]
            
            df['created_at'] = pd.to_datetime(df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
            
            st.dataframe(df, use_container_width=True, height=400)
            
            st.divider()
            
            col_exp, col_json, col_del, col_pdf = st.columns(4)

            with col_exp:
                full_dump = pd.read_sql("SELECT * FROM results r JOIN patients p ON p.id = r.patient_id", conn)
                st.download_button("📥 Export CSV", full_dump.to_csv(index=False),
                                 "nipt_registry.csv", "text/csv")

            with col_json:
                # Generate comprehensive JSON export
                with sqlite3.connect(DB_FILE) as json_conn:
                    json_query = """
                        SELECT r.id as report_id, r.created_at as report_date,
                               p.full_name, p.mrn_id, p.age, p.weight_kg, p.height_cm, p.bmi, p.weeks,
                               p.clinical_notes, r.panel_type, r.qc_status, r.qc_details, r.qc_advice,
                               r.t21_res, r.t18_res, r.t13_res, r.sca_res,
                               r.cnv_json, r.rat_json, r.full_z_json, r.final_summary
                        FROM results r
                        JOIN patients p ON p.id = r.patient_id
                        ORDER BY r.id DESC
                    """
                    json_df = pd.read_sql(json_query, json_conn)

                    # Convert to structured JSON
                    json_records = []
                    for _, row in json_df.iterrows():
                        record = {
                            'report_id': int(row['report_id']) if pd.notna(row['report_id']) else None,
                            'report_date': str(row['report_date']) if pd.notna(row['report_date']) else None,
                            'patient': {
                                'name': str(row['full_name']) if pd.notna(row['full_name']) else None,
                                'mrn': str(row['mrn_id']) if pd.notna(row['mrn_id']) else None,
                                'age': int(row['age']) if pd.notna(row['age']) else None,
                                'weight_kg': float(row['weight_kg']) if pd.notna(row['weight_kg']) else None,
                                'height_cm': int(row['height_cm']) if pd.notna(row['height_cm']) else None,
                                'bmi': float(row['bmi']) if pd.notna(row['bmi']) else None,
                                'gestational_weeks': int(row['weeks']) if pd.notna(row['weeks']) else None,
                                'clinical_notes': str(row['clinical_notes']) if pd.notna(row['clinical_notes']) else None,
                            },
                            'test_info': {
                                'panel_type': str(row['panel_type']) if pd.notna(row['panel_type']) else None,
                                'qc_status': str(row['qc_status']) if pd.notna(row['qc_status']) else None,
                                'qc_details': str(row['qc_details']) if pd.notna(row['qc_details']) else None,
                                'qc_advice': str(row['qc_advice']) if pd.notna(row['qc_advice']) else None,
                            },
                            'results': {
                                'trisomy_21': str(row['t21_res']) if pd.notna(row['t21_res']) else None,
                                'trisomy_18': str(row['t18_res']) if pd.notna(row['t18_res']) else None,
                                'trisomy_13': str(row['t13_res']) if pd.notna(row['t13_res']) else None,
                                'sca': str(row['sca_res']) if pd.notna(row['sca_res']) else None,
                                'cnv_findings': json.loads(row['cnv_json']) if pd.notna(row['cnv_json']) else [],
                                'rat_findings': json.loads(row['rat_json']) if pd.notna(row['rat_json']) else [],
                                'z_scores': json.loads(row['full_z_json']) if pd.notna(row['full_z_json']) else {},
                                'final_summary': str(row['final_summary']) if pd.notna(row['final_summary']) else None,
                            }
                        }
                        json_records.append(record)

                    json_export = {
                        'export_date': datetime.now().isoformat(),
                        'total_records': len(json_records),
                        'exported_by': st.session_state.user['username'],
                        'records': json_records
                    }

                st.download_button("📤 Export JSON", json.dumps(json_export, indent=2),
                                 "nipt_registry.json", "application/json")
            
            with col_del:
                with st.expander("🗑️ Delete Record"):
                    del_id = st.number_input("Report ID", 1, key="del_input")
                    if st.button("Confirm Delete", type="secondary"):
                        ok, msg = delete_record(del_id)
                        if ok: 
                            st.success(msg)
                            st.rerun()
                        else: 
                            st.error(msg)
            
            with col_pdf:
                with st.expander("📄 Generate PDF"):
                    pdf_id = st.number_input("Report ID", 1, key="pdf_input")
                    if st.button("Generate"):
                        pdf_data = generate_pdf_report(pdf_id)
                        if pdf_data:
                            st.download_button("Download PDF", pdf_data,
                                             f"Report_{pdf_id}.pdf", "application/pdf")
                        else:
                            st.error("Report not found")

            # ===== PATIENT VIEW/EDIT SECTION =====
            st.divider()
            st.subheader("👤 Patient Details & Edit")

            # Get list of unique patients
            with sqlite3.connect(DB_FILE) as patient_conn:
                patients_query = """
                    SELECT DISTINCT p.id, p.mrn_id, p.full_name, COUNT(r.id) as result_count
                    FROM patients p
                    LEFT JOIN results r ON r.patient_id = p.id
                    GROUP BY p.id
                    ORDER BY p.full_name
                """
                patients_df = pd.read_sql(patients_query, patient_conn)

            if not patients_df.empty:
                # Create selection options
                patient_options = {f"{row['mrn_id']} - {row['full_name']} ({row['result_count']} results)": row['id']
                                   for _, row in patients_df.iterrows()}

                selected_patient_label = st.selectbox(
                    "Select Patient to View/Edit",
                    options=["-- Select a patient --"] + list(patient_options.keys()),
                    key="patient_selector"
                )

                if selected_patient_label != "-- Select a patient --":
                    patient_id = patient_options[selected_patient_label]
                    patient_details = get_patient_details(patient_id)

                    if patient_details:
                        with st.expander("📋 View & Edit Patient Information", expanded=True):
                            st.info(f"Patient ID: {patient_details['mrn']} | Created: {patient_details.get('created_at', 'N/A')[:10] if patient_details.get('created_at') else 'N/A'}")

                            with st.form(key="edit_patient_form"):
                                col1, col2 = st.columns(2)
                                with col1:
                                    edit_name = st.text_input("Full Name", value=patient_details.get('name', ''))
                                    edit_age = st.number_input("Age", min_value=15, max_value=60,
                                        value=int(patient_details.get('age', 30)) if patient_details.get('age') else 30)
                                    edit_weight = st.number_input("Weight (kg)", min_value=30.0, max_value=200.0,
                                        value=float(patient_details.get('weight', 65.0)) if patient_details.get('weight') else 65.0)
                                with col2:
                                    edit_weeks = st.number_input("Gestational Weeks", min_value=9, max_value=42,
                                        value=int(patient_details.get('weeks', 12)) if patient_details.get('weeks') else 12)
                                    edit_height = st.number_input("Height (cm)", min_value=100, max_value=220,
                                        value=int(patient_details.get('height', 165)) if patient_details.get('height') else 165)
                                    if edit_weight > 0 and edit_height > 0:
                                        edit_bmi = round(edit_weight / ((edit_height/100)**2), 1)
                                        st.metric("BMI (calculated)", edit_bmi)
                                    else:
                                        edit_bmi = 0.0

                                edit_notes = st.text_area("Clinical Notes",
                                    value=patient_details.get('notes', '') or '',
                                    height=100)

                                if st.form_submit_button("💾 Update Patient Information", type="primary"):
                                    update_data = {
                                        'name': edit_name,
                                        'age': edit_age,
                                        'weight': edit_weight,
                                        'height': edit_height,
                                        'bmi': edit_bmi,
                                        'weeks': edit_weeks,
                                        'notes': edit_notes
                                    }
                                    success, message = update_patient(patient_id, update_data)
                                    if success:
                                        st.success(f"✅ {message}")
                                        st.rerun()
                                    else:
                                        st.error(f"❌ Failed to update: {message}")

                        # Show patient's test results
                        with st.expander("📊 Patient Test Results", expanded=False):
                            with sqlite3.connect(DB_FILE) as results_conn:
                                results_query = """
                                    SELECT r.id, r.created_at, r.panel_type, r.qc_status,
                                           r.t21_res, r.t18_res, r.t13_res, r.sca_res, r.final_summary
                                    FROM results r
                                    WHERE r.patient_id = ?
                                    ORDER BY r.created_at DESC
                                """
                                patient_results = pd.read_sql(results_query, results_conn, params=(patient_id,))

                            if not patient_results.empty:
                                patient_results['created_at'] = pd.to_datetime(patient_results['created_at']).dt.strftime('%Y-%m-%d %H:%M')
                                st.dataframe(patient_results, use_container_width=True)
                            else:
                                st.info("No test results found for this patient")
        else:
            st.info("No records found")
    
    # TAB 3: ANALYTICS
    with tabs[2]:
        render_analytics_dashboard()
    
    # TAB 4: BATCH IMPORT
    with tabs[3]:
        st.header("📂 Batch Import")
        
        import_method = st.radio("Import Method", 
                                 ["📄 From PDF Reports", "📊 From CSV/Excel Template"],
                                 horizontal=True)
        
        st.divider()
        
        # ===== PDF IMPORT =====
        if import_method == "📄 From PDF Reports":
            st.subheader("Import from PDF Reports")
            st.markdown("""
            Upload one or multiple PDF reports. The system extracts:
            - **Patient Info**: Name, MRN/File Number, Age, Weight, Height, BMI, Gestational Weeks
            - **Sequencing Metrics**: Reads, Cff, GC%, QS, Unique Rate, Error Rate
            - **Z-Scores**: All 22 autosomes + XX/XY
            - **Findings**: CNVs, RATs, SCA type
            - **Results**: QC Status, Final Interpretation
            
            Files are automatically **grouped by patient MRN/File Number**.
            """)
            
            uploaded_pdfs = st.file_uploader(
                "Upload PDF Report(s)", 
                type=['pdf'], 
                accept_multiple_files=True,
                help="Select one or more PDF files - they will be grouped by patient file number"
            )
            
            if uploaded_pdfs:
                st.info(f"📁 {len(uploaded_pdfs)} file(s) selected")
                
                if st.button("🔍 Extract & Preview Data", type="primary"):
                    with st.spinner("Extracting comprehensive data from PDFs..."):
                        result = parse_pdf_batch(uploaded_pdfs)
                    
                    patients = result['patients']
                    errors = result['errors']
                    
                    if errors:
                        st.warning(f"⚠️ {len(errors)} file(s) had issues:")
                        for err in errors:
                            st.caption(f"• {err}")
                    
                    if patients:
                        st.success(f"✅ Extracted data for {len(patients)} patient(s)")
                        st.info("📝 **Edit Mode**: You can modify any extracted values before importing. Changes are saved when you click 'Confirm & Import'.")

                        # Store patients data in session state for import
                        st.session_state.pdf_import_data = patients

                        # Check for duplicates and show warnings
                        for mrn in patients.keys():
                            exists, existing_patient = check_duplicate_patient(mrn)
                            if exists:
                                st.warning(f"⚠️ Patient ID '{mrn}' already exists as '{existing_patient['name']}' "
                                          f"with {existing_patient['result_count']} result(s). "
                                          f"Importing will add new results to existing patient record.")

                        # Helper function to safely get values with defaults
                        def safe_int(val, default=0):
                            try:
                                return int(val) if val and val > 0 else default
                            except (TypeError, ValueError):
                                return default

                        def safe_float(val, default=0.0):
                            try:
                                return float(val) if val and val > 0 else default
                            except (TypeError, ValueError):
                                return default

                        # Show patients grouped by MRN with editable fields using forms
                        for mrn, records in patients.items():
                            with st.expander(f"📋 Patient: {mrn} - {records[0]['patient_name']} ({len(records)} file(s))", expanded=True):
                                for idx, record in enumerate(records, 1):
                                    edit_key = f"{mrn}_{idx}"
                                    st.markdown(f"**File {idx}: {record['source_file']}**")

                                    # Use form to prevent crashes on edit
                                    with st.form(key=f"form_{edit_key}"):
                                        st.markdown("##### Patient Information")
                                        p_col1, p_col2, p_col3, p_col4 = st.columns(4)
                                        with p_col1:
                                            edit_name = st.text_input("Name", value=record.get('patient_name', ''))
                                        with p_col2:
                                            edit_age = st.number_input("Age", min_value=15, max_value=60,
                                                value=safe_int(record.get('age'), 30))
                                        with p_col3:
                                            edit_weeks = st.number_input("Weeks", min_value=9, max_value=24,
                                                value=safe_int(record.get('weeks'), 12))
                                        with p_col4:
                                            panel_options = ["NIPT Basic", "NIPT Standard", "NIPT Plus", "NIPT Pro"]
                                            current_panel = record.get('panel', 'NIPT Standard')
                                            panel_idx = panel_options.index(current_panel) if current_panel in panel_options else 1
                                            edit_panel = st.selectbox("Panel", panel_options, index=panel_idx)

                                        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
                                        with m_col1:
                                            edit_weight = st.number_input("Weight (kg)", min_value=30.0, max_value=200.0,
                                                value=safe_float(record.get('weight'), 65.0))
                                        with m_col2:
                                            edit_height = st.number_input("Height (cm)", min_value=100, max_value=220,
                                                value=safe_int(record.get('height'), 165))
                                        with m_col3:
                                            if edit_weight > 0 and edit_height > 0:
                                                edit_bmi = round(edit_weight / ((edit_height/100)**2), 1)
                                                st.metric("BMI (auto)", edit_bmi)
                                            else:
                                                edit_bmi = 0.0
                                                st.metric("BMI", "N/A")
                                        with m_col4:
                                            sca_options = ["XX", "XY", "XO", "XXX", "XXY", "XYY"]
                                            current_sca = record.get('sca_type', 'XX')
                                            sca_idx = sca_options.index(current_sca) if current_sca in sca_options else 0
                                            edit_sca = st.selectbox("SCA Type", sca_options, index=sca_idx)

                                        st.markdown("##### Sequencing Metrics")
                                        q_col1, q_col2, q_col3, q_col4, q_col5, q_col6 = st.columns(6)
                                        with q_col1:
                                            edit_reads = st.number_input("Reads (M)", min_value=0.0, max_value=100.0,
                                                value=safe_float(record.get('reads'), 10.0))
                                        with q_col2:
                                            edit_cff = st.number_input("Cff %", min_value=0.0, max_value=50.0,
                                                value=safe_float(record.get('cff'), 10.0))
                                        with q_col3:
                                            edit_gc = st.number_input("GC %", min_value=0.0, max_value=100.0,
                                                value=safe_float(record.get('gc'), 41.0))
                                        with q_col4:
                                            edit_qs = st.number_input("QS", min_value=0.0, max_value=10.0,
                                                value=safe_float(record.get('qs'), 1.0))
                                        with q_col5:
                                            edit_uniq = st.number_input("Unique %", min_value=0.0, max_value=100.0,
                                                value=safe_float(record.get('unique_rate'), 80.0))
                                        with q_col6:
                                            edit_error = st.number_input("Error %", min_value=0.0, max_value=10.0,
                                                value=safe_float(record.get('error_rate'), 0.2))

                                        st.markdown("##### Z-Scores (Trisomies)")
                                        z_col1, z_col2, z_col3, z_col4, z_col5 = st.columns(5)
                                        z_scores_orig = record.get('z_scores', {})
                                        with z_col1:
                                            edit_z21 = st.number_input("Z-21", min_value=-10.0, max_value=20.0,
                                                value=safe_float(z_scores_orig.get(21, z_scores_orig.get('21', 0.0))), format="%.2f")
                                        with z_col2:
                                            edit_z18 = st.number_input("Z-18", min_value=-10.0, max_value=20.0,
                                                value=safe_float(z_scores_orig.get(18, z_scores_orig.get('18', 0.0))), format="%.2f")
                                        with z_col3:
                                            edit_z13 = st.number_input("Z-13", min_value=-10.0, max_value=20.0,
                                                value=safe_float(z_scores_orig.get(13, z_scores_orig.get('13', 0.0))), format="%.2f")
                                        with z_col4:
                                            edit_zxx = st.number_input("Z-XX", min_value=-10.0, max_value=20.0,
                                                value=safe_float(z_scores_orig.get('XX', 0.0)), format="%.2f")
                                        with z_col5:
                                            edit_zxy = st.number_input("Z-XY", min_value=-10.0, max_value=20.0,
                                                value=safe_float(z_scores_orig.get('XY', 0.0)), format="%.2f")

                                        edit_notes = st.text_area("Clinical Notes",
                                            value=record.get('notes', ''),
                                            help="Enter clinical observations like NT measurements, ultrasound findings, etc.")

                                        # Save form data button
                                        if st.form_submit_button("💾 Save Changes for this Record"):
                                            # Store edited data in session state
                                            if 'pdf_edit_data' not in st.session_state:
                                                st.session_state.pdf_edit_data = {}
                                            st.session_state.pdf_edit_data[edit_key] = {
                                                'patient_name': edit_name,
                                                'age': edit_age,
                                                'weeks': edit_weeks,
                                                'panel': edit_panel,
                                                'weight': edit_weight,
                                                'height': edit_height,
                                                'bmi': edit_bmi,
                                                'sca_type': edit_sca,
                                                'reads': edit_reads,
                                                'cff': edit_cff,
                                                'gc': edit_gc,
                                                'qs': edit_qs,
                                                'unique_rate': edit_uniq,
                                                'error_rate': edit_error,
                                                'z_scores': {21: edit_z21, 18: edit_z18, 13: edit_z13, 'XX': edit_zxx, 'XY': edit_zxy},
                                                'notes': edit_notes,
                                                'cnv_findings': record.get('cnv_findings', []),
                                                'rat_findings': record.get('rat_findings', []),
                                                'source_file': record.get('source_file', '')
                                            }
                                            st.success(f"✅ Changes saved for {edit_name}")

                                    # Show CNV/RAT findings outside form
                                    if record.get('cnv_findings') or record.get('rat_findings'):
                                        with st.expander("View CNV/RAT Findings"):
                                            if record.get('cnv_findings'):
                                                st.markdown("**CNV Findings:**")
                                                for cnv in record['cnv_findings']:
                                                    st.caption(f"• Size: {cnv['size']} Mb, Ratio: {cnv['ratio']}%")
                                            if record.get('rat_findings'):
                                                st.markdown("**RAT Findings:**")
                                                for rat in record['rat_findings']:
                                                    st.caption(f"• Chr {rat['chr']}: Z = {rat['z']}")

                                    st.divider()

                        st.warning("⚠️ Click 'Save Changes' in each record form to save edits, then click 'Import All' below")

                        col1, col2 = st.columns(2)
                        with col1:
                            if st.button("✅ Confirm & Import All to Registry", type="primary"):
                                success, fail = 0, 0
                                config = load_config()
                                edit_data = st.session_state.get('pdf_edit_data', {})

                                for mrn, records in patients.items():
                                    for idx, original_data in enumerate(records, 1):
                                        try:
                                            edit_key = f"{mrn}_{idx}"
                                            # Use edited data if available, otherwise use original
                                            data = edit_data.get(edit_key, original_data)

                                            # Get Z-scores
                                            z_scores = data.get('z_scores', {})
                                            z_21 = safe_float(z_scores.get(21, z_scores.get('21', 0.0)))
                                            z_18 = safe_float(z_scores.get(18, z_scores.get('18', 0.0)))
                                            z_13 = safe_float(z_scores.get(13, z_scores.get('13', 0.0)))
                                            z_xx = safe_float(z_scores.get('XX', 0.0))
                                            z_xy = safe_float(z_scores.get('XY', 0.0))

                                            # Analyze
                                            t21, _ = analyze_trisomy(config, z_21, "21")
                                            t18, _ = analyze_trisomy(config, z_18, "18")
                                            t13, _ = analyze_trisomy(config, z_13, "13")
                                            cff_val = safe_float(data.get('cff'), 10.0)
                                            sca, _ = analyze_sca(config, data.get('sca_type', 'XX'), z_xx, z_xy, cff_val)

                                            # Process CNVs and RATs
                                            analyzed_cnvs = []
                                            for cnv in data.get('cnv_findings', []):
                                                msg, _, _ = analyze_cnv(cnv['size'], cnv['ratio'])
                                                analyzed_cnvs.append(f"{cnv['size']}Mb ({cnv['ratio']}%) -> {msg}")

                                            analyzed_rats = []
                                            for rat in data.get('rat_findings', []):
                                                msg, _ = analyze_rat(config, rat['chr'], rat['z'])
                                                analyzed_rats.append(f"Chr {rat['chr']} (Z:{rat['z']}) -> {msg}")

                                            # Run QC
                                            reads_val = safe_float(data.get('reads'), 10.0)
                                            gc_val = safe_float(data.get('gc'), 41.0)
                                            qs_val = safe_float(data.get('qs'), 1.0)
                                            uniq_val = safe_float(data.get('unique_rate'), 80.0)
                                            error_val = safe_float(data.get('error_rate'), 0.2)

                                            qc_s, qc_m, qc_a = check_qc_metrics(
                                                config, data.get('panel', 'NIPT Standard'),
                                                reads_val, cff_val, gc_val, qs_val, uniq_val, error_val, False
                                            )

                                            # Determine final result
                                            final = "NEGATIVE"
                                            if "POSITIVE" in (t21 + t18 + t13 + sca):
                                                final = "POSITIVE DETECTED"
                                            if qc_s == "FAIL":
                                                final = "INVALID (QC FAIL)"

                                            p_data = {
                                                'name': data.get('patient_name', 'Unknown'),
                                                'id': mrn,
                                                'age': safe_int(data.get('age'), 30),
                                                'weight': safe_float(data.get('weight'), 65.0),
                                                'height': safe_int(data.get('height'), 165),
                                                'bmi': safe_float(data.get('bmi'), 0.0),
                                                'weeks': safe_int(data.get('weeks'), 12),
                                                'notes': f"Imported from: {data.get('source_file', 'PDF')}. {data.get('notes', '')}"
                                            }

                                            r_data = {
                                                'panel': data.get('panel', 'NIPT Standard'),
                                                'qc_status': qc_s,
                                                'qc_msgs': qc_m,
                                                'qc_advice': qc_a
                                            }

                                            c_data = {
                                                't21': t21, 't18': t18, 't13': t13, 'sca': sca,
                                                'cnv_list': analyzed_cnvs, 'rat_list': analyzed_rats, 'final': final
                                            }

                                            full_z = {21: z_21, 18: z_18, 13: z_13, 'XX': z_xx, 'XY': z_xy}

                                            # QC metrics for PDF report
                                            qc_metrics = {
                                                'reads': reads_val, 'cff': cff_val, 'gc': gc_val,
                                                'qs': qs_val, 'unique_rate': uniq_val, 'error_rate': error_val
                                            }

                                            rid, msg = save_result(p_data, r_data, c_data, full_z, qc_metrics=qc_metrics)
                                            if rid:
                                                success += 1
                                            else:
                                                st.warning(f"⚠️ {data.get('patient_name', 'Unknown')}: {msg}")

                                        except Exception as e:
                                            st.error(f"Failed to import {data.get('patient_name', 'Unknown')}: {e}")
                                            fail += 1

                                st.success(f"✅ Import Complete: {success} records imported, {fail} failed")
                                log_audit("PDF_IMPORT", f"Imported {success} records from {len(uploaded_pdfs)} PDFs",
                                         st.session_state.user['id'])

                                # Clean up
                                for key in ['pdf_import_data', 'pdf_edit_data']:
                                    if key in st.session_state:
                                        del st.session_state[key]

                        with col2:
                            if st.button("❌ Cancel"):
                                for key in ['pdf_import_data', 'pdf_edit_data']:
                                    if key in st.session_state:
                                        del st.session_state[key]
                                st.rerun()
                    else:
                        st.error("❌ Could not extract data from any PDFs")
            
            st.divider()
            st.markdown("""
            **📋 Comprehensive Extraction Includes:**
            - ✅ All patient demographics (name, MRN, age, weight, height, BMI, weeks)
            - ✅ Complete sequencing metrics (reads, Cff, GC, QS, unique rate, error rate)
            - ✅ Z-scores for all 22 autosomes (Chr 1-22)
            - ✅ Sex chromosome Z-scores (XX, XY)
            - ✅ CNV findings with size and ratio
            - ✅ RAT findings with chromosome and Z-score
            - ✅ QC status and final results
            - ✅ Clinical notes (nuchal translucency, ultrasound findings, etc.)

            **📝 Edit Before Import:**
            - All extracted values are **editable** before import
            - Modify patient info, sequencing metrics, Z-scores
            - Add clinical notes including NT measurements
            - BMI auto-calculates from weight/height

            **📁 Intelligent Grouping:**
            - Files are automatically grouped by **Patient MRN/File Number**
            - Multiple reports for the same patient are shown together
            - Each file is processed separately but organized by patient

            **⚠️ Requirements:**
            - PDFs must contain **searchable text** (not scanned images)
            - Patient MRN/File Number must be present for grouping
            """)
        
        # ===== CSV/EXCEL IMPORT =====
        else:
            st.subheader("Import from CSV/Excel Template")
        template = {
            'Patient Name': ['Example'], 'MRN': ['12345'], 'Age': [30], 
            'Weight': [65], 'Height': [165], 'Weeks': [12], 'Panel': ['NIPT Standard'],
            'Reads': [10.5], 'Cff': [12.0], 'GC': [41.0], 'QS': [1.2], 
            'Unique': [80.0], 'Error': [0.2],
            'SCA Type': ['XX'], 'Z-XX': [0.0], 'Z-XY': [0.0]
        }
        for i in range(1, 23): template[f'Z-{i}'] = [0.0]
        
        template_df = pd.DataFrame(template)
        st.download_button("📥 Download Template", 
                          template_df.to_csv(index=False), 
                          "NIPT_Template.csv", "text/csv")

        st.markdown("#### 2. Upload File")
        uploaded = st.file_uploader("Upload CSV/Excel", type=['csv', 'xlsx'])
        
        if uploaded and st.button("▶️ Process Batch"):
            try:
                if uploaded.name.endswith('.csv'):
                    df_in = pd.read_csv(uploaded)
                else:
                    df_in = pd.read_excel(uploaded)
                
                success, fail = 0, 0
                bar = st.progress(0)
                status = st.empty()
                
                for idx, row in df_in.iterrows():
                    try:
                        status.text(f"Processing {idx+1}/{len(df_in)}")
                        
                        p_data = {
                            'name': row.get('Patient Name'), 'id': str(row.get('MRN')), 
                            'age': row.get('Age'), 'weight': row.get('Weight'), 
                            'height': row.get('Height'), 'bmi': 0, 
                            'weeks': row.get('Weeks'), 'notes': ''
                        }
                        
                        z_map = {i: row.get(f'Z-{i}', 0.0) for i in range(1, 23)}
                        z_map['XX'] = row.get('Z-XX', 0.0)
                        z_map['XY'] = row.get('Z-XY', 0.0)

                        t21, _ = analyze_trisomy(config, z_map[21], "21")
                        t18, _ = analyze_trisomy(config, z_map[18], "18")
                        t13, _ = analyze_trisomy(config, z_map[13], "13")
                        sca, _ = analyze_sca(config, row.get('SCA Type', 'XX'), 
                                           z_map['XX'], z_map['XY'], row.get('Cff', 10))

                        rats = []
                        for ch, z in z_map.items():
                            if isinstance(ch, int) and ch not in [13, 18, 21]:
                                msg, _ = analyze_rat(config, ch, z)
                                if "POSITIVE" in msg or "Ambiguous" in msg:
                                    rats.append(f"Chr {ch} (Z:{z}) -> {msg}")

                        qc_s, qc_m, qc_a = check_qc_metrics(
                            config, row.get('Panel'), row.get('Reads'), row.get('Cff'), 
                            row.get('GC'), row.get('QS'), row.get('Unique'), 
                            row.get('Error'), False
                        )
                        
                        final = "NEGATIVE"
                        if "POSITIVE" in (t21 + t18 + t13 + sca): final = "POSITIVE"
                        if qc_s == "FAIL": final = "INVALID"

                        save_result(p_data, 
                                   {'panel': row.get('Panel'), 'qc_status': qc_s, 
                                    'qc_msgs': qc_m, 'qc_advice': qc_a},
                                   {'t21': t21, 't18': t18, 't13': t13, 'sca': sca, 
                                    'cnv_list': [], 'rat_list': rats, 'final': final},
                                   full_z=z_map)
                        success += 1
                    except:
                        fail += 1
                    bar.progress((idx + 1) / len(df_in))
                
                status.empty()
                st.success(f"✅ Success: {success} | ❌ Failed: {fail}")
                log_audit("BATCH_IMPORT", f"Processed {success}/{len(df_in)}", 
                         st.session_state.user['id'])
            except Exception as e:
                st.error(f"Error: {e}")
    
    # TAB 5: SETTINGS
    with tabs[4]:
        st.header("⚙️ Settings")
        
        st.subheader("Clinical Thresholds")
        
        with st.form("config_form"):
            st.markdown("**QC Thresholds**")
            c1, c2 = st.columns(2)
            new_cff = c1.number_input("Min CFF (%)", 0.0, 10.0, 
                                      config['QC_THRESHOLDS']['MIN_CFF'])
            gc_min = c2.number_input("GC Min (%)", 0.0, 50.0, 
                                     config['QC_THRESHOLDS']['GC_RANGE'][0])
            gc_max = c2.number_input("GC Max (%)", 0.0, 50.0, 
                                     config['QC_THRESHOLDS']['GC_RANGE'][1])
            
            st.markdown("**Panel Read Limits (M)**")
            c3, c4, c5, c6 = st.columns(4)
            basic = c3.number_input("Basic", 1, 20, config['PANEL_READ_LIMITS']['NIPT Basic'])
            standard = c4.number_input("Standard", 1, 20, config['PANEL_READ_LIMITS']['NIPT Standard'])
            plus = c5.number_input("Plus", 1, 20, config['PANEL_READ_LIMITS']['NIPT Plus'])
            pro = c6.number_input("Pro", 1, 20, config['PANEL_READ_LIMITS']['NIPT Pro'])
            
            st.markdown("**Clinical Thresholds**")
            c7, c8 = st.columns(2)
            tris_low = c7.number_input("Trisomy Low Risk", 0.0, 10.0, 
                                       config['CLINICAL_THRESHOLDS']['TRISOMY_LOW'])
            tris_amb = c7.number_input("Trisomy Ambiguous", 0.0, 10.0, 
                                       config['CLINICAL_THRESHOLDS']['TRISOMY_AMBIGUOUS'])
            sca_thresh = c8.number_input("SCA Threshold", 0.0, 10.0, 
                                         config['CLINICAL_THRESHOLDS']['SCA_THRESHOLD'])
            rat_pos = c8.number_input("RAT Positive", 0.0, 15.0, 
                                      config['CLINICAL_THRESHOLDS']['RAT_POSITIVE'])
            
            if st.form_submit_button("💾 Save Configuration"):
                new_config = DEFAULT_CONFIG.copy()
                new_config['QC_THRESHOLDS']['MIN_CFF'] = new_cff
                new_config['QC_THRESHOLDS']['GC_RANGE'] = [gc_min, gc_max]
                new_config['PANEL_READ_LIMITS'] = {
                    'NIPT Basic': basic, 'NIPT Standard': standard,
                    'NIPT Plus': plus, 'NIPT Pro': pro
                }
                new_config['CLINICAL_THRESHOLDS']['TRISOMY_LOW'] = tris_low
                new_config['CLINICAL_THRESHOLDS']['TRISOMY_AMBIGUOUS'] = tris_amb
                new_config['CLINICAL_THRESHOLDS']['SCA_THRESHOLD'] = sca_thresh
                new_config['CLINICAL_THRESHOLDS']['RAT_POSITIVE'] = rat_pos
                
                if save_config(new_config):
                    st.success("✅ Configuration saved")
                    log_audit("CONFIG_UPDATE", "Updated thresholds", 
                             st.session_state.user['id'])
                    st.rerun()
                else:
                    st.error("Failed to save")
        
        st.divider()
        
        st.subheader("User Management")

        # Password Change Section (available to all users)
        st.markdown("**🔑 Change Password**")
        with st.form("change_password_form"):
            current_password = st.text_input("Current Password", type="password", key="curr_pwd")
            new_password_1 = st.text_input("New Password", type="password", key="new_pwd1")
            new_password_2 = st.text_input("Confirm New Password", type="password", key="new_pwd2")

            if st.form_submit_button("Update Password"):
                if not current_password or not new_password_1 or not new_password_2:
                    st.error("All fields are required")
                elif new_password_1 != new_password_2:
                    st.error("New passwords do not match")
                elif len(new_password_1) < 6:
                    st.error("New password must be at least 6 characters")
                else:
                    # Verify current password
                    with sqlite3.connect(DB_FILE) as conn:
                        c = conn.cursor()
                        c.execute("SELECT password_hash FROM users WHERE id = ?",
                                 (st.session_state.user['id'],))
                        row = c.fetchone()
                        if row and verify_password(current_password, row[0]):
                            # Update password
                            new_hash = hash_password(new_password_1)
                            c.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                                     (new_hash, st.session_state.user['id']))
                            st.success("✅ Password updated successfully")
                            log_audit("PASSWORD_CHANGE", "User changed password",
                                     st.session_state.user['id'])
                        else:
                            st.error("Current password is incorrect")

        st.divider()

        # Admin-only user management
        if st.session_state.user['role'] == 'admin':
            st.markdown("**👥 Create New User**")
            with st.form("new_user_form"):
                new_username = st.text_input("Username")
                new_password = st.text_input("Password", type="password")
                new_fullname = st.text_input("Full Name")
                new_role = st.selectbox("Role", ["technician", "geneticist", "admin"],
                                       help="Technician: Data entry and analysis. Geneticist: Analysis, review and approval. Admin: Full access including user management.")

                if st.form_submit_button("Create User"):
                    if new_username and new_password:
                        if len(new_password) < 6:
                            st.error("Password must be at least 6 characters")
                        else:
                            try:
                                with sqlite3.connect(DB_FILE) as conn:
                                    c = conn.cursor()
                                    c.execute("""
                                        INSERT INTO users (username, password_hash, full_name, role, created_at)
                                        VALUES (?, ?, ?, ?, ?)
                                    """, (new_username, hash_password(new_password),
                                         new_fullname, new_role, datetime.now().isoformat()))
                                    st.success(f"✅ User '{new_username}' created with role '{new_role}'")
                                    log_audit("CREATE_USER", f"Created user {new_username} with role {new_role}",
                                             st.session_state.user['id'])
                            except sqlite3.IntegrityError:
                                st.error("Username already exists")
                    else:
                        st.error("Username and password required")

            # List existing users
            st.markdown("**📋 Existing Users**")
            with sqlite3.connect(DB_FILE) as conn:
                users_df = pd.read_sql("""
                    SELECT id, username, full_name, role, created_at, last_login
                    FROM users ORDER BY id
                """, conn)

            if not users_df.empty:
                st.dataframe(users_df, use_container_width=True, height=200)
        else:
            st.info("Admin access required for user management")
        
        st.divider()
        
        st.subheader("Audit Log")
        with sqlite3.connect(DB_FILE) as conn:
            audit = pd.read_sql("""
                SELECT a.timestamp, u.username, a.action, a.details 
                FROM audit_log a 
                LEFT JOIN users u ON u.id = a.user_id 
                ORDER BY a.id DESC LIMIT 50
            """, conn)
        
        if not audit.empty:
            st.dataframe(audit, use_container_width=True, height=300)
        else:
            st.info("No audit entries")

if __name__ == "__main__":
    main()
