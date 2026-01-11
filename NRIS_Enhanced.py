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

def save_result(patient: Dict, results: Dict, clinical: Dict, full_z: Optional[Dict] = None) -> int:
    """Save with audit logging."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            
            c.execute("SELECT id FROM patients WHERE mrn_id = ?", (patient['id'],))
            existing = c.fetchone()
            
            if existing:
                patient_db_id = existing[0]
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
            
            c.execute("""
                INSERT INTO results 
                (patient_id, panel_type, qc_status, qc_details, qc_advice,
                 t21_res, t18_res, t13_res, sca_res, 
                 cnv_json, rat_json, full_z_json, final_summary, created_at, created_by) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                patient_db_id, results['panel'], results['qc_status'], 
                str(results['qc_msgs']), results['qc_advice'],
                clinical['t21'], clinical['t18'], clinical['t13'], clinical['sca'],
                json.dumps(clinical['cnv_list']), json.dumps(clinical['rat_list']), 
                json.dumps(full_z) if full_z else "{}", clinical['final'],
                datetime.now().isoformat(), st.session_state.user['id']
            ))
            result_id = c.lastrowid
            
            log_audit("SAVE_RESULT", f"Created result {result_id}", st.session_state.user['id'])
            return result_id
    except Exception as e:
        st.error(f"Database error: {e}")
        return 0

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
    """Extract comprehensive patient and test data from PDF report."""
    try:
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text()
        
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
            'notes': ''
        }
        
        # ===== PATIENT DEMOGRAPHICS =====
        # Extract patient name (multiple patterns)
        name_patterns = [
            r'(?:Patient|Name)[:\s]+([A-Za-z\s\-\']+?)(?:\n|MRN|ID|Age|\||$)',
            r'Full\s+Name[:\s]+([A-Za-z\s\-\']+?)(?:\n|MRN)',
        ]
        for pattern in name_patterns:
            name_match = re.search(pattern, text, re.IGNORECASE)
            if name_match:
                data['patient_name'] = name_match.group(1).strip()
                break
        
        # Extract MRN / Patient ID (multiple patterns)
        mrn_patterns = [
            r'MRN[:\s]+([A-Za-z0-9\-]+)',
            r'(?:Patient\s+)?ID[:\s]+([A-Za-z0-9\-]+)',
            r'File\s+(?:Number|No)[:\s]+([A-Za-z0-9\-]+)',
        ]
        for pattern in mrn_patterns:
            mrn_match = re.search(pattern, text, re.IGNORECASE)
            if mrn_match:
                data['mrn'] = mrn_match.group(1).strip()
                break
        
        # Extract age
        age_match = re.search(r'Age[:\s]+(\d+)', text, re.IGNORECASE)
        if age_match:
            data['age'] = int(age_match.group(1))
        
        # Extract weight
        weight_match = re.search(r'Weight[:\s]+(\d+\.?\d*)\s*(?:kg|KG)', text, re.IGNORECASE)
        if weight_match:
            data['weight'] = float(weight_match.group(1))
        
        # Extract height
        height_match = re.search(r'Height[:\s]+(\d+)\s*(?:cm|CM)', text, re.IGNORECASE)
        if height_match:
            data['height'] = int(height_match.group(1))
        
        # Extract BMI
        bmi_match = re.search(r'BMI[:\s]+(\d+\.?\d*)', text, re.IGNORECASE)
        if bmi_match:
            data['bmi'] = float(bmi_match.group(1))
        
        # Extract gestational weeks (multiple patterns)
        weeks_patterns = [
            r'(?:Gestational\s+Age|Gest\.\s+Age|Weeks)[:\s]+(\d+)\s*(?:weeks?|wks?)?',
            r'(\d+)\s*weeks?\s*(?:gestation|pregnant)',
        ]
        for pattern in weeks_patterns:
            weeks_match = re.search(pattern, text, re.IGNORECASE)
            if weeks_match:
                data['weeks'] = int(weeks_match.group(1))
                break
        
        # ===== SEQUENCING METRICS =====
        # Extract panel type
        panel_patterns = [
            r'Panel[:\s]+(NIPT\s+\w+)',
            r'Test\s+Type[:\s]+(NIPT\s+\w+)',
        ]
        for pattern in panel_patterns:
            panel_match = re.search(pattern, text, re.IGNORECASE)
            if panel_match:
                data['panel'] = panel_match.group(1).strip()
                break
        
        # Extract sequencing metrics
        reads_match = re.search(r'Reads?[:\s]+(\d+\.?\d*)\s*M?', text, re.IGNORECASE)
        if reads_match:
            data['reads'] = float(reads_match.group(1))
        
        cff_patterns = [
            r'(?:Cff|Fetal\s+Fraction)[:\s]+(\d+\.?\d*)\s*%?',
            r'FF[:\s]+(\d+\.?\d*)\s*%?',
        ]
        for pattern in cff_patterns:
            cff_match = re.search(pattern, text, re.IGNORECASE)
            if cff_match:
                data['cff'] = float(cff_match.group(1))
                break
        
        gc_match = re.search(r'GC[:\s]+(\d+\.?\d*)\s*%?', text, re.IGNORECASE)
        if gc_match:
            data['gc'] = float(gc_match.group(1))
        
        qs_patterns = [
            r'QS[:\s]+(\d+\.?\d*)',
            r'Quality\s+Score[:\s]+(\d+\.?\d*)',
        ]
        for pattern in qs_patterns:
            qs_match = re.search(pattern, text, re.IGNORECASE)
            if qs_match:
                data['qs'] = float(qs_match.group(1))
                break
        
        unique_match = re.search(r'Unique(?:\s+Rate)?[:\s]+(\d+\.?\d*)\s*%?', text, re.IGNORECASE)
        if unique_match:
            data['unique_rate'] = float(unique_match.group(1))
        
        error_match = re.search(r'Error(?:\s+Rate)?[:\s]+(\d+\.?\d*)\s*%?', text, re.IGNORECASE)
        if error_match:
            data['error_rate'] = float(error_match.group(1))
        
        # ===== Z-SCORES (ALL AUTOSOMES) =====
        # Extract Z-scores for main trisomies
        for chrom in [13, 18, 21]:
            z_patterns = [
                rf'(?:Z[-\s]?{chrom}|Chr\s*{chrom}\s*Z)[:\s]+(-?\d+\.?\d*)',
                rf'Trisomy\s+{chrom}.*?(?:Z[-\s]?Score)?[:\s]+(-?\d+\.?\d*)',
                rf'T{chrom}.*?Z[:\s]+(-?\d+\.?\d*)',
            ]
            for pattern in z_patterns:
                z_match = re.search(pattern, text, re.IGNORECASE)
                if z_match:
                    data['z_scores'][chrom] = float(z_match.group(1))
                    break
        
        # Extract Z-scores for ALL autosomes (1-22, excluding 13, 18, 21 already captured)
        for chrom in range(1, 23):
            if chrom in [13, 18, 21]:
                continue  # Already captured
            
            z_patterns = [
                rf'(?:Z[-\s]?{chrom}|Chr\s*{chrom}\s*Z)[:\s]+(-?\d+\.?\d*)',
                rf'Chromosome\s+{chrom}.*?Z[:\s]+(-?\d+\.?\d*)',
            ]
            for pattern in z_patterns:
                z_match = re.search(pattern, text, re.IGNORECASE)
                if z_match:
                    data['z_scores'][chrom] = float(z_match.group(1))
                    break
        
        # Extract SCA Z-scores
        z_xx_patterns = [
            r'Z[-\s]?XX[:\s]+(-?\d+\.?\d*)',
            r'XX\s+Z[-\s]?Score[:\s]+(-?\d+\.?\d*)',
        ]
        for pattern in z_xx_patterns:
            z_xx_match = re.search(pattern, text, re.IGNORECASE)
            if z_xx_match:
                data['z_scores']['XX'] = float(z_xx_match.group(1))
                break
        
        z_xy_patterns = [
            r'Z[-\s]?XY[:\s]+(-?\d+\.?\d*)',
            r'XY\s+Z[-\s]?Score[:\s]+(-?\d+\.?\d*)',
        ]
        for pattern in z_xy_patterns:
            z_xy_match = re.search(pattern, text, re.IGNORECASE)
            if z_xy_match:
                data['z_scores']['XY'] = float(z_xy_match.group(1))
                break
        
        # ===== SCA TYPE DETECTION =====
        sca_patterns = [
            (r'Turner|Monosomy\s+X', 'XO'),
            (r'Triple\s+X|XXX', 'XXX'),
            (r'Klinefelter|XXY', 'XXY'),
            (r'XYY|Jacob', 'XYY'),
            (r'(?:Sex.*?Male|Gender.*?Male)(?!.*Female)', 'XY'),
            (r'(?:Sex.*?Female|Gender.*?Female)', 'XX'),
        ]
        for pattern, sca_type in sca_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                data['sca_type'] = sca_type
                break
        
        # ===== CNV FINDINGS =====
        # Look for CNV sections
        cnv_section = re.search(r'CNV.*?:(.*?)(?:RAT|RARE|Final|$)', text, re.IGNORECASE | re.DOTALL)
        if cnv_section:
            cnv_text = cnv_section.group(1)
            # Extract CNV entries (format: "Size: X.X Mb, Ratio: Y.Y%")
            cnv_matches = re.finditer(r'(\d+\.?\d*)\s*(?:Mb|MB).*?(\d+\.?\d*)\s*%', cnv_text)
            for match in cnv_matches:
                size = float(match.group(1))
                ratio = float(match.group(2))
                data['cnv_findings'].append({'size': size, 'ratio': ratio})
        
        # ===== RAT FINDINGS =====
        # Look for RAT/Rare Autosome sections
        rat_section = re.search(r'(?:RAT|Rare.*?Autosome).*?:(.*?)(?:Final|CNV|Interpretation|$)', text, re.IGNORECASE | re.DOTALL)
        if rat_section:
            rat_text = rat_section.group(1)
            # Extract RAT entries (format: "Chr X: Z-score Y.Y")
            rat_matches = re.finditer(r'Chr(?:omosome)?\s*(\d+).*?Z.*?(-?\d+\.?\d*)', rat_text, re.IGNORECASE)
            for match in rat_matches:
                chrom = int(match.group(1))
                z_score = float(match.group(2))
                if chrom not in [13, 18, 21]:  # Exclude main trisomies
                    data['rat_findings'].append({'chr': chrom, 'z': z_score})
        
        # ===== QC STATUS & RESULTS =====
        qc_patterns = [
            r'QC\s+Status[:\s]+(\w+)',
            r'Quality\s+Control[:\s]+(\w+)',
        ]
        for pattern in qc_patterns:
            qc_match = re.search(pattern, text, re.IGNORECASE)
            if qc_match:
                data['qc_status'] = qc_match.group(1).upper()
                break
        
        # Extract final result
        result_patterns = [
            r'Final\s+(?:Interpretation|Result|Call)[:\s]+([A-Z\s\(\)]+)',
            r'Conclusion[:\s]+([A-Z\s\(\)]+)',
        ]
        for pattern in result_patterns:
            result_match = re.search(pattern, text, re.IGNORECASE)
            if result_match:
                data['final_result'] = result_match.group(1).strip()
                break
        
        # Extract clinical notes
        notes_patterns = [
            r'(?:Clinical\s+)?Notes[:\s]+(.+?)(?:\n\n|={3,}|$)',
            r'Comments[:\s]+(.+?)(?:\n\n|={3,}|$)',
        ]
        for pattern in notes_patterns:
            notes_match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if notes_match:
                data['notes'] = notes_match.group(1).strip()[:500]
                break
        
        return data
        
    except Exception as e:
        st.error(f"PDF extraction error in {filename}: {e}")
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

def generate_pdf_report(report_id: int) -> Optional[bytes]:
    """Generate PDF report."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            query = """
                SELECT r.id, p.full_name, p.mrn_id, p.age, p.weeks, r.created_at, p.clinical_notes,
                       r.panel_type, r.qc_status, r.qc_details, r.qc_advice,
                       r.t21_res, r.t18_res, r.t13_res, r.sca_res,
                       r.cnv_json, r.rat_json, r.full_z_json, r.final_summary
                FROM results r 
                JOIN patients p ON p.id = r.patient_id 
                WHERE r.id = ?
            """
            df = pd.read_sql(query, conn, params=(report_id,))
            
        if df.empty: return None

        row = df.iloc[0]
        cnvs = json.loads(row['cnv_json'])
        rats = json.loads(row['rat_json'])
        z_data = json.loads(row['full_z_json']) if row['full_z_json'] else {}

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch)
        story = []
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, 
                                     textColor=colors.HexColor('#2C3E50'), alignment=TA_CENTER)
        
        story.append(Paragraph("CLINICAL GENETICS LABORATORY", title_style))
        story.append(Paragraph("NIPT Report", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        info_data = [
            ['Report ID:', str(row['id']), 'Date:', row['created_at'][:10]],
            ['Panel:', row['panel_type'], '', '']
        ]
        info_table = Table(info_data, colWidths=[1.2*inch, 2.3*inch, 1*inch, 2*inch])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 0.2*inch))
        
        story.append(Paragraph("PATIENT INFORMATION", styles['Heading2']))
        patient_data = [
            ['Name:', row['full_name'], 'MRN:', row['mrn_id']],
            ['Age:', f"{row['age']}", 'Weeks:', f"{row['weeks']}"],
        ]
        patient_table = Table(patient_data, colWidths=[1.2*inch, 2.3*inch, 1.2*inch, 1.8*inch])
        patient_table.setStyle(TableStyle([('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold')]))
        story.append(patient_table)
        story.append(Spacer(1, 0.2*inch))
        
        story.append(Paragraph("RESULTS", styles['Heading2']))
        results_data = [
            ['Test', 'Result', 'Z-Score'],
            ['Trisomy 21', row['t21_res'], str(z_data.get('21', 'N/A'))],
            ['Trisomy 18', row['t18_res'], str(z_data.get('18', 'N/A'))],
            ['Trisomy 13', row['t13_res'], str(z_data.get('13', 'N/A'))],
            ['SCA', row['sca_res'], '']
        ]
        
        results_table = Table(results_data, colWidths=[2*inch, 3*inch, 1.5*inch])
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(results_table)
        story.append(Spacer(1, 0.2*inch))
        
        story.append(Paragraph(f"<b>FINAL: {row['final_summary']}</b>", styles['Normal']))
        
        doc.build(story)
        return buffer.getvalue()
        
    except Exception as e:
        st.error(f"PDF error: {e}")
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

            rid = save_result(p_data, r_data, c_data, full_z)
            
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
            
            col_exp, col_del, col_pdf = st.columns(3)
            
            with col_exp:
                full_dump = pd.read_sql("SELECT * FROM results r JOIN patients p ON p.id = r.patient_id", conn)
                st.download_button("📥 Export CSV", full_dump.to_csv(index=False), 
                                 "nipt_registry.csv", "text/csv")
            
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
                        
                        # Show patients grouped by MRN
                        for mrn, records in patients.items():
                            with st.expander(f"📋 Patient: {mrn} - {records[0]['patient_name']} ({len(records)} file(s))", expanded=True):
                                # Show patient summary
                                first_record = records[0]
                                
                                col1, col2, col3, col4 = st.columns(4)
                                col1.metric("Name", first_record['patient_name'])
                                col2.metric("MRN/File #", mrn)
                                col3.metric("Age", first_record['age'] if first_record['age'] > 0 else "N/A")
                                col4.metric("Weeks", first_record['weeks'] if first_record['weeks'] > 0 else "N/A")
                                
                                # Show all files for this patient
                                for idx, record in enumerate(records, 1):
                                    st.markdown(f"**File {idx}: {record['source_file']}**")
                                    
                                    # Create comprehensive preview
                                    preview_data = {
                                        'Weight (kg)': record['weight'] if record['weight'] > 0 else 'N/A',
                                        'Height (cm)': record['height'] if record['height'] > 0 else 'N/A',
                                        'BMI': record['bmi'] if record['bmi'] > 0 else 'N/A',
                                        'Panel': record['panel'],
                                        'Reads (M)': record['reads'] if record['reads'] > 0 else 'N/A',
                                        'Cff %': record['cff'] if record['cff'] > 0 else 'N/A',
                                        'GC %': record['gc'] if record['gc'] > 0 else 'N/A',
                                        'QS': record['qs'] if record['qs'] > 0 else 'N/A',
                                        'Unique %': record['unique_rate'] if record['unique_rate'] > 0 else 'N/A',
                                        'Error %': record['error_rate'] if record['error_rate'] > 0 else 'N/A',
                                        'SCA Type': record['sca_type'],
                                        'QC Status': record['qc_status'] if record['qc_status'] else 'N/A',
                                        'Final Result': record['final_result'] if record['final_result'] else 'N/A',
                                    }
                                    
                                    col_a, col_b = st.columns(2)
                                    with col_a:
                                        st.json(preview_data)
                                    
                                    with col_b:
                                        # Show Z-scores
                                        st.markdown("**Z-Scores:**")
                                        z_display = {}
                                        
                                        # Main trisomies
                                        for chrom in [21, 18, 13]:
                                            if chrom in record['z_scores']:
                                                z_display[f"Chr {chrom}"] = record['z_scores'][chrom]
                                        
                                        # All other autosomes
                                        for chrom in range(1, 23):
                                            if chrom not in [13, 18, 21] and chrom in record['z_scores']:
                                                z_display[f"Chr {chrom}"] = record['z_scores'][chrom]
                                        
                                        # SCA
                                        if 'XX' in record['z_scores']:
                                            z_display['XX'] = record['z_scores']['XX']
                                        if 'XY' in record['z_scores']:
                                            z_display['XY'] = record['z_scores']['XY']
                                        
                                        if z_display:
                                            st.json(z_display)
                                        else:
                                            st.caption("No Z-scores found")
                                        
                                        # CNV findings
                                        if record['cnv_findings']:
                                            st.markdown("**CNV Findings:**")
                                            for cnv in record['cnv_findings']:
                                                st.caption(f"• Size: {cnv['size']} Mb, Ratio: {cnv['ratio']}%")
                                        
                                        # RAT findings
                                        if record['rat_findings']:
                                            st.markdown("**RAT Findings:**")
                                            for rat in record['rat_findings']:
                                                st.caption(f"• Chr {rat['chr']}: Z = {rat['z']}")
                                    
                                    if record['notes']:
                                        st.caption(f"**Notes:** {record['notes']}")
                                    
                                    st.divider()
                        
                        # Store in session state
                        st.session_state.pdf_import_data = patients
                        
                        st.warning("⚠️ Review all extracted data above before importing")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            if st.button("✅ Confirm & Import All to Registry", type="primary"):
                                success, fail = 0, 0
                                config = load_config()
                                
                                for mrn, records in patients.items():
                                    for data in records:
                                        try:
                                            # Get Z-scores
                                            z_21 = data['z_scores'].get(21, 0.0)
                                            z_18 = data['z_scores'].get(18, 0.0)
                                            z_13 = data['z_scores'].get(13, 0.0)
                                            z_xx = data['z_scores'].get('XX', 0.0)
                                            z_xy = data['z_scores'].get('XY', 0.0)
                                            
                                            # Analyze
                                            t21, _ = analyze_trisomy(config, z_21, "21")
                                            t18, _ = analyze_trisomy(config, z_18, "18")
                                            t13, _ = analyze_trisomy(config, z_13, "13")
                                            sca, _ = analyze_sca(config, data['sca_type'], z_xx, z_xy, 
                                                               data['cff'] if data['cff'] > 0 else 10.0)
                                            
                                            # Process CNVs
                                            analyzed_cnvs = []
                                            for cnv in data['cnv_findings']:
                                                msg, _, _ = analyze_cnv(cnv['size'], cnv['ratio'])
                                                analyzed_cnvs.append(f"{cnv['size']}Mb ({cnv['ratio']}%) -> {msg}")
                                            
                                            # Process RATs
                                            analyzed_rats = []
                                            for rat in data['rat_findings']:
                                                msg, _ = analyze_rat(config, rat['chr'], rat['z'])
                                                analyzed_rats.append(f"Chr {rat['chr']} (Z:{rat['z']}) -> {msg}")
                                            
                                            # QC
                                            if data['qc_status']:
                                                qc_s = data['qc_status']
                                                qc_m = ["Imported from PDF"]
                                                qc_a = "Verify QC details"
                                            else:
                                                # Run QC if we have metrics
                                                if data['reads'] > 0 and data['cff'] > 0:
                                                    qc_s, qc_m, qc_a = check_qc_metrics(
                                                        config, data['panel'], data['reads'], data['cff'],
                                                        data['gc'], data['qs'], data['unique_rate'],
                                                        data['error_rate'], False
                                                    )
                                                else:
                                                    qc_s, qc_m, qc_a = "PASS", ["Imported from PDF"], "None"
                                            
                                            # Final result
                                            if data['final_result']:
                                                final = data['final_result']
                                            else:
                                                final = "NEGATIVE"
                                                if "POSITIVE" in (t21 + t18 + t13 + sca):
                                                    final = "POSITIVE DETECTED"
                                            
                                            p_data = {
                                                'name': data['patient_name'],
                                                'id': mrn,
                                                'age': data['age'],
                                                'weight': data['weight'],
                                                'height': data['height'],
                                                'bmi': data['bmi'],
                                                'weeks': data['weeks'],
                                                'notes': f"Imported from: {data['source_file']}. {data['notes']}"
                                            }
                                            
                                            r_data = {
                                                'panel': data['panel'],
                                                'qc_status': qc_s,
                                                'qc_msgs': qc_m,
                                                'qc_advice': qc_a
                                            }
                                            
                                            c_data = {
                                                't21': t21,
                                                't18': t18,
                                                't13': t13,
                                                'sca': sca,
                                                'cnv_list': analyzed_cnvs,
                                                'rat_list': analyzed_rats,
                                                'final': final
                                            }
                                            
                                            # Build full Z-score dictionary
                                            full_z = data['z_scores'].copy()
                                            
                                            save_result(p_data, r_data, c_data, full_z)
                                            success += 1
                                            
                                        except Exception as e:
                                            st.error(f"Failed to import {data.get('patient_name', 'Unknown')}: {e}")
                                            fail += 1
                                
                                st.success(f"✅ Import Complete: {success} records imported, {fail} failed")
                                log_audit("PDF_IMPORT", f"Imported {success} records from {len(uploaded_pdfs)} PDFs", 
                                         st.session_state.user['id'])
                                
                                if 'pdf_import_data' in st.session_state:
                                    del st.session_state.pdf_import_data
                        
                        with col2:
                            if st.button("❌ Cancel"):
                                if 'pdf_import_data' in st.session_state:
                                    del st.session_state.pdf_import_data
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
            - ✅ Clinical notes
            
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
        if st.session_state.user['role'] == 'admin':
            with st.form("new_user_form"):
                st.markdown("**Create New User**")
                new_username = st.text_input("Username")
                new_password = st.text_input("Password", type="password")
                new_fullname = st.text_input("Full Name")
                new_role = st.selectbox("Role", ["technician", "admin"])
                
                if st.form_submit_button("Create User"):
                    if new_username and new_password:
                        try:
                            with sqlite3.connect(DB_FILE) as conn:
                                c = conn.cursor()
                                c.execute("""
                                    INSERT INTO users (username, password_hash, full_name, role, created_at)
                                    VALUES (?, ?, ?, ?, ?)
                                """, (new_username, hash_password(new_password), 
                                     new_fullname, new_role, datetime.now().isoformat()))
                                st.success(f"✅ User '{new_username}' created")
                                log_audit("CREATE_USER", f"Created user {new_username}", 
                                         st.session_state.user['id'])
                        except sqlite3.IntegrityError:
                            st.error("Username already exists")
                    else:
                        st.error("Username and password required")
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
