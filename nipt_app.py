"""
NIPT Result Interpretation Software
---------------------------
A local Streamlit dashboard for analyzing Non-Invasive Prenatal Testing (NIPT) data.
Implements strict clinical thresholds for Trisomies 13/18/21, SCAs, and CNVs.

Author: [AzizElGhezal]
"""

import sqlite3
import json
import io
import random
from datetime import datetime
from typing import Tuple, List, Dict, Any, Optional

import streamlit as st
import pandas as pd

# Database Configuration
DB_FILE = "nipt_registry.db"

# Clinical Thresholds (Strict Protocol)
QC_THRESHOLDS = {
    'MIN_CFF': 3.5,
    'GC_RANGE': (37.0, 44.0),
    'MIN_UNIQ_RATE': 68.0,
    'MAX_ERROR_RATE': 1.0,
    'QS_LIMIT_NEG': 1.7,
    'QS_LIMIT_POS': 2.0
}

PANEL_READ_LIMITS = {
    "NIPT Basic": 5,
    "NIPT Standard": 7,
    "NIPT Plus": 12,
    "NIPT Pro": 20
}

def init_database() -> None:
    """Initializes the SQLite database schema if it doesn't exist."""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS patients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mrn_id TEXT,
                full_name TEXT,
                age INTEGER,
                weight_kg REAL,
                height_cm INTEGER,
                bmi REAL,
                weeks INTEGER,
                clinical_notes TEXT,
                created_at TEXT
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
                FOREIGN KEY(patient_id) REFERENCES patients(id)
            )
        ''')
        
        # Migration: Ensure columns exist for older DB versions
        try:
            c.execute("ALTER TABLE results ADD COLUMN qc_advice TEXT")
        except sqlite3.OperationalError:
            pass
            
        try:
            c.execute("ALTER TABLE results ADD COLUMN full_z_json TEXT")
        except sqlite3.OperationalError:
            pass

def save_result(patient: Dict, results: Dict, clinical: Dict, full_z: Optional[Dict] = None) -> int:
    """Saves a new patient record and analysis result to the database."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            
            # Insert Patient
            c.execute("""
                INSERT INTO patients 
                (mrn_id, full_name, age, weight_kg, height_cm, bmi, weeks, clinical_notes, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                patient['id'], patient['name'], patient['age'], patient['weight'], 
                patient['height'], patient['bmi'], patient['weeks'], patient['notes'],
                datetime.now().strftime("%Y-%m-%d %H:%M")
            ))
            patient_db_id = c.lastrowid
            
            # Insert Results
            c.execute("""
                INSERT INTO results 
                (patient_id, panel_type, qc_status, qc_details, qc_advice,
                 t21_res, t18_res, t13_res, sca_res, 
                 cnv_json, rat_json, full_z_json, final_summary) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                patient_db_id, 
                results['panel'], 
                results['qc_status'], 
                str(results['qc_msgs']), 
                results['qc_advice'],
                clinical['t21'], 
                clinical['t18'], 
                clinical['t13'], 
                clinical['sca'],
                json.dumps(clinical['cnv_list']), 
                json.dumps(clinical['rat_list']), 
                json.dumps(full_z) if full_z else "{}", 
                clinical['final']
            ))
            return c.lastrowid
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
        return 0

def delete_record(report_id: int) -> Tuple[bool, str]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT patient_id FROM results WHERE id = ?", (report_id,))
            row = c.fetchone()
            if not row:
                return False, "Report ID not found."
            
            patient_id = row[0]
            c.execute("DELETE FROM results WHERE id = ?", (report_id,))
            c.execute("DELETE FROM patients WHERE id = ?", (patient_id,))
            return True, f"Record {report_id} deleted successfully."
    except Exception as e:
        return False, str(e)

# --- Analysis Logic ---

def check_qc_metrics(panel: str, reads: float, cff: float, gc: float, qs: float, 
                    uniq: float, error: float, is_positive: bool) -> Tuple[str, List[str], str]:
    """Evaluates sample quality against strict lab thresholds."""
    issues = []
    advice = []
    
    # 1. Read Depth
    min_reads = PANEL_READ_LIMITS.get(panel, 5)
    if reads < min_reads:
        issues.append(f"HARD: Reads {reads}M < {min_reads}M")
        advice.append("Resequencing")

    # 2. Fetal Fraction
    if cff < QC_THRESHOLDS['MIN_CFF']:
        issues.append(f"HARD: Cff {cff}% < {QC_THRESHOLDS['MIN_CFF']}%")
        advice.append("Resample")

    # 3. GC Content
    if not (QC_THRESHOLDS['GC_RANGE'][0] <= gc <= QC_THRESHOLDS['GC_RANGE'][1]):
        issues.append(f"HARD: GC {gc}% out of range")
        advice.append("Re-library")

    # 4. Quality Score (QS)
    qs_limit = QC_THRESHOLDS['QS_LIMIT_POS'] if is_positive else QC_THRESHOLDS['QS_LIMIT_NEG']
    if qs >= qs_limit:
        issues.append(f"HARD: QS {qs} >= {qs_limit}")
        advice.append("Re-library")

    # Soft QC
    if uniq < QC_THRESHOLDS['MIN_UNIQ_RATE']:
        issues.append(f"SOFT: UniqueRate {uniq}% Low")
    if error > QC_THRESHOLDS['MAX_ERROR_RATE']:
        issues.append(f"SOFT: ErrorRate {error}% High")

    status = "FAIL" if any("HARD" in i for i in issues) else ("WARNING" if issues else "PASS")
    advice_str = " / ".join(set(advice)) if advice else "None"
    
    return status, issues, advice_str

def analyze_trisomy(z_score: float, chrom: str) -> str:
    """Determines risk level for T13, T18, T21."""
    if pd.isna(z_score): return "Invalid Data"
    if z_score < 2.58: return "Low Risk"
    if z_score < 6.0: return f"High Risk (Ambiguous Z:{z_score}) -> Re-library ({chrom})"
    return "POSITIVE -> Report Positive"

def analyze_sca(sca_type: str, z_xx: float, z_xy: float, cff: float) -> str:
    """Analyzes Sex Chromosome Aneuploidies."""
    if cff < 3.5: return "INVALID (Cff < 3.5%) -> Resample"
    
    if sca_type == "XX": return "Negative (Female)"
    if sca_type == "XY": return "Negative (Male)"
    
    if sca_type == "XO":
        return "POSITIVE (Turner XO)" if z_xx >= 4.5 else "Ambiguous XO (Z-XX < 4.5) -> Re-library"
    
    if sca_type == "XXX":
        return "POSITIVE (Triple X)" if z_xx >= 4.5 else "Ambiguous XXX (Z-XX < 4.5) -> Re-library"
        
    if sca_type in ["XXY", "XYY"]: return f"POSITIVE ({sca_type})"
    
    return "Ambiguous SCA -> Review Clinical Data"

def analyze_rat(chrom: int, z_score: float) -> str:
    """Analyzes Rare Autosomal Trisomies (RATs)."""
    if z_score >= 8.0: return "POSITIVE"
    if z_score > 4.5: return "Ambiguous (High Risk) -> Re-library"
    return "Low Risk"

def analyze_cnv(size: float, ratio: float) -> Tuple[str, float]:
    """Analyzes Copy Number Variations based on size/ratio thresholds."""
    if size >= 10: threshold = 6.0
    elif size > 7: threshold = 8.0
    elif size > 3.5: threshold = 10.0
    else: threshold = 12.0
    
    if ratio >= threshold:
        return f"High Risk (Ratio {ratio}%) -> Re-library", threshold
    return "Low Risk", threshold

def generate_report(report_id: int) -> Tuple[Optional[str], str]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            query = """
                SELECT r.id, p.full_name, p.mrn_id, p.age, p.weeks, p.created_at, p.clinical_notes,
                       r.panel_type, r.qc_status, r.qc_details, r.qc_advice,
                       r.t21_res, r.t18_res, r.t13_res, r.sca_res,
                       r.cnv_json, r.rat_json, r.full_z_json, r.final_summary
                FROM results r 
                JOIN patients p ON p.id = r.patient_id 
                WHERE r.id = ?
            """
            df = pd.read_sql(query, conn, params=(report_id,))
            
        if df.empty:
            return None, "Report not found."

        row = df.iloc[0]
        cnvs = json.loads(row['cnv_json'])
        rats = json.loads(row['rat_json'])
        z_data = json.loads(row['full_z_json']) if row['full_z_json'] else {}

        # Clean QC text
        qc_clean = str(row['qc_details']).replace("[", "").replace("]", "").replace("'", "").replace('"', "")
        if not qc_clean: qc_clean = "None"

        # Report Building
        report = [
            "==================================================",
            "          CLINICAL GENETICS REPORT",
            "==================================================",
            f"Report ID:     {row['id']}",
            f"Date:          {row['created_at']}",
            f"Panel:         {row['panel_type']}",
            "--------------------------------------------------",
            "PATIENT INFORMATION",
            f"Name:          {row['full_name']}",
            f"MRN:           {row['mrn_id']}",
            f"Age:           {row['age']} | Gest. Age: {row['weeks']} weeks",
            f"Notes:         {row['clinical_notes']}",
            "--------------------------------------------------",
            "QUALITY CONTROL",
            f"Status:        {row['qc_status']}",
            f"Details:       {qc_clean}",
            f"Action:        {row['qc_advice']}",
            "--------------------------------------------------",
            "SCREENING RESULTS",
            f"Trisomy 21:    {row['t21_res']} (Z: {z_data.get('21', 'N/A')})",
            f"Trisomy 18:    {row['t18_res']} (Z: {z_data.get('18', 'N/A')})",
            f"Trisomy 13:    {row['t13_res']} (Z: {z_data.get('13', 'N/A')})",
            f"Sex Chroms:    {row['sca_res']}",
        ]
        
        if 'XX' in z_data:
            report.append(f"   - Z-XX: {z_data.get('XX')} | Z-XY: {z_data.get('XY')}")
            
        report.append("\nCNV FINDINGS:")
        report.extend([f" - {i}" for i in cnvs] if cnvs else [" - None Detected"])
        
        report.append("\nRARE AUTOSOMES (RAT):")
        report.extend([f" - {i}" for i in rats] if rats else [" - None Detected"])
        
        report.append("==================================================")
        report.append(f"FINAL INTERPRETATION: {row['final_summary']}")
        report.append("==================================================")
        
        return "\n".join(report), "Success"

    except Exception as e:
        return None, str(e)

# --- UI Layout ---

def main():
    st.set_page_config(page_title="NIPT Analyzer", layout="wide", page_icon="🧬")
    init_database()

    # Initialize Session State
    if 'cnv_list' not in st.session_state: st.session_state.cnv_list = []
    if 'rat_list' not in st.session_state: st.session_state.rat_list = []
    if 'analysis_complete' not in st.session_state: st.session_state.analysis_complete = False
    if 'current_result' not in st.session_state: st.session_state.current_result = {}
    if 'last_report_id' not in st.session_state: st.session_state.last_report_id = None

    tab_entry, tab_registry, tab_import = st.tabs(["📝 Analysis Entry", "📊 Registry", "📂 Batch Import"])

    # ---------------- TAB 1: ENTRY ----------------
    with tab_entry:
        st.title("🧬 NIPT Diagnostic System")
        
        # Patient Info
        with st.container():
            c1, c2, c3 = st.columns(3)
            p_name = c1.text_input("Patient Name")
            p_id = c2.text_input("MRN / ID")
            p_age = c3.number_input("Age", 15, 60, 30)
            
            c4, c5, c6, c7 = st.columns(4)
            p_weight = c4.number_input("Weight (kg)", 0.0, 200.0, 0.0)
            p_height = c5.number_input("Height (cm)", 0, 250, 0)
            bmi = round(p_weight / ((p_height/100)**2), 2) if p_height > 0 else 0
            c6.metric("BMI", f"{bmi}" if bmi > 0 else "--")
            p_weeks = c7.number_input("Weeks", 0, 42, 12)
            p_notes = st.text_area("Clinical Notes", height=80)
        
        st.markdown("---")

        # Sequencing Metrics
        st.subheader("1. Sequencing Metrics")
        panel_type = st.selectbox("Panel Type", list(PANEL_READ_LIMITS.keys()))
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        reads = m1.number_input("Reads (M)", 0.0, 100.0, 8.0)
        cff = m2.number_input("Cff %", 0.0, 50.0, 10.0)
        gc = m3.number_input("GC %", 0.0, 100.0, 40.0)
        qs = m4.number_input("QS", 0.0, 10.0, 1.0)
        uniq_rate = m5.number_input("Unique %", 0.0, 100.0, 75.0)
        error_rate = m6.number_input("Error %", 0.0, 5.0, 0.1)

        st.markdown("---")

        # Z-Scores
        c_tri, c_sca = st.columns(2)
        with c_tri:
            st.subheader("2. Trisomy Z-Scores")
            z21 = st.number_input("Z-21", -10.0, 50.0, 0.5)
            z18 = st.number_input("Z-18", -10.0, 50.0, 0.5)
            z13 = st.number_input("Z-13", -10.0, 50.0, 0.5)
        
        with c_sca:
            st.subheader("3. Sex Chromosomes")
            sca_type = st.selectbox("Detected Type", ["XX", "XY", "XO", "XXX", "XXY", "XYY"])
            z1, z2 = st.columns(2)
            z_xx = z1.number_input("Z-Score XX", -10.0, 50.0, 0.0)
            z_xy = z2.number_input("Z-Score XY", -10.0, 50.0, 0.0)

        st.markdown("---")

        # Dynamic Findings
        d1, d2 = st.columns(2)
        with d1:
            st.subheader("4. CNV Findings")
            with st.form("cnv_form"):
                sz = st.number_input("Size (Mb)", 0.0)
                rt = st.number_input("Ratio (%)", 0.0)
                if st.form_submit_button("Add CNV") and sz > 0:
                    st.session_state.cnv_list.append({"size": sz, "ratio": rt})
                    st.rerun()
            
            for i, item in enumerate(st.session_state.cnv_list):
                st.text(f"CNV {i+1}: {item['size']}Mb | Ratio: {item['ratio']}%")
            if st.session_state.cnv_list and st.button("Clear CNVs"):
                st.session_state.cnv_list = []

        with d2:
            st.subheader("5. Rare Autosomes (RAT)")
            with st.form("rat_form"):
                r_chr = st.number_input("Chr #", 1, 22, 7)
                r_z = st.number_input("Z-Score", 0.0)
                if st.form_submit_button("Add RAT") and r_z > 0:
                    st.session_state.rat_list.append({"chr": r_chr, "z": r_z})
                    st.rerun()
            
            for i, item in enumerate(st.session_state.rat_list):
                st.text(f"RAT {i+1}: Chr {item['chr']} | Z: {item['z']}")
            if st.session_state.rat_list and st.button("Clear RATs"):
                st.session_state.rat_list = []

        st.markdown("---")

        if st.button("💾 SAVE & ANALYZE", type="primary"):
            # Run Analysis Logic
            t21_res = analyze_trisomy(z21, "21")
            t18_res = analyze_trisomy(z18, "18")
            t13_res = analyze_trisomy(z13, "13")
            sca_res = analyze_sca(sca_type, z_xx, z_xy, cff)
            
            analyzed_cnvs = []
            is_cnv_high = False
            for item in st.session_state.cnv_list:
                msg, _ = analyze_cnv(item['size'], item['ratio'])
                if "Re-library" in msg: is_cnv_high = True
                analyzed_cnvs.append(f"{item['size']}Mb ({item['ratio']}%) -> {msg}")

            analyzed_rats = []
            is_rat_high = False
            for item in st.session_state.rat_list:
                msg = analyze_rat(item['chr'], item['z'])
                if "POSITIVE" in msg or "Ambiguous" in msg: is_rat_high = True
                analyzed_rats.append(f"Chr {item['chr']} (Z:{item['z']}) -> {msg}")

            # Risk Assessment
            all_flags = t21_res + t18_res + t13_res + sca_res
            is_positive = "POSITIVE" in all_flags
            is_high_risk = "High Risk" in all_flags or is_cnv_high or is_rat_high or "Re-library" in all_flags
            
            qc_stat, qc_msg, qc_advice = check_qc_metrics(
                panel_type, reads, cff, gc, qs, uniq_rate, error_rate, is_positive or is_high_risk
            )
            
            final_summary = "NEGATIVE"
            if is_positive: final_summary = "POSITIVE DETECTED"
            elif is_high_risk: final_summary = "HIGH RISK / AMBIGUOUS (SEE ADVICE)"
            elif "Ambiguous" in all_flags: final_summary = "AMBIGUOUS (LAB CHECK)"
            if qc_stat == "FAIL": final_summary = "INVALID (QC FAIL)"

            # Save
            p_data = {'name': p_name, 'id': p_id, 'age': p_age, 'weight': p_weight, 
                      'height': p_height, 'bmi': bmi, 'weeks': p_weeks, 'notes': p_notes}
            r_data = {'panel': panel_type, 'qc_status': qc_stat, 'qc_msgs': qc_msg, 'qc_advice': qc_advice}
            c_data = {'t21': t21_res, 't18': t18_res, 't13': t13_res, 'sca': sca_res, 
                      'cnv_list': analyzed_cnvs, 'rat_list': analyzed_rats, 'final': final_summary}
            
            full_z = {13: z13, 18: z18, 21: z21, 'XX': z_xx, 'XY': z_xy}
            for r in st.session_state.rat_list: full_z[r['chr']] = r['z']

            rid = save_result(p_data, r_data, c_data, full_z)
            
            if rid:
                st.toast("Record Saved Successfully")
                st.session_state.last_report_id = rid
                st.session_state.current_result = {'clinical': c_data, 'qc': {'status': qc_stat, 'msg': qc_msg, 'advice': qc_advice}}
                st.session_state.analysis_complete = True
                st.session_state.cnv_list = []
                st.session_state.rat_list = []
        
        # Display Results
        if st.session_state.analysis_complete:
            res = st.session_state.current_result['clinical']
            qc = st.session_state.current_result['qc']
            
            st.divider()
            if qc['status'] == "FAIL":
                st.error(f"QC FAILED: {qc['msg']}")
                st.error(f"ACTION REQUIRED: {qc['advice']}")
            else:
                st.success(f"QC PASSED ({qc['status']})")

            # Result Table
            rows = [
                ["Trisomy 21", res['t21']],
                ["Trisomy 18", res['t18']],
                ["Trisomy 13", res['t13']],
                ["Sex Chromosomes", res['sca']]
            ]
            for i in res['cnv_list']: rows.append(["CNV", i])
            for i in res['rat_list']: rows.append(["Rare Autosome", i])
            
            df_res = pd.DataFrame(rows, columns=["Test", "Result"])
            
            def color_rows(val):
                s = str(val)
                if "POSITIVE" in s: return 'background-color: #ffcccc; color: #8b0000; font-weight: bold'
                if "Re-library" in s or "Resample" in s: return 'background-color: #fff3cd; color: #856404'
                return ''
            
            st.dataframe(df_res.style.map(color_rows), use_container_width=True)
            st.info(f"FINAL CALL: {res['final']}")

            if st.session_state.last_report_id:
                txt, _ = generate_report(st.session_state.last_report_id)
                if txt:
                    st.download_button("📥 Download Report", txt, f"Report_{st.session_state.last_report_id}.txt")

    # ---------------- TAB 2: REGISTRY ----------------
    with tab_registry:
        st.header("📊 Patient Registry")
        if st.button("🔄 Refresh Data"): st.rerun()

        with sqlite3.connect(DB_FILE) as conn:
            query = """
                SELECT r.id, p.created_at, p.full_name, p.mrn_id, r.panel_type, 
                       r.qc_status, r.qc_details, r.final_summary 
                FROM results r 
                JOIN patients p ON p.id = r.patient_id 
                ORDER BY r.id DESC
            """
            df = pd.read_sql(query, conn)
        
        if not df.empty:
            # Clean display columns
            df['qc_details'] = df['qc_details'].apply(
                lambda x: str(x).replace("[", "").replace("]", "").replace("'", "").replace('"', "")
            )
            df['qc_details'] = df['qc_details'].replace("", "None")
            
            st.dataframe(df, use_container_width=True)
            
            # Export
            full_dump = pd.read_sql("SELECT * FROM results r JOIN patients p ON p.id = r.patient_id", conn)
            st.download_button("📥 Export CSV", full_dump.to_csv(index=False), "nipt_registry.csv", "text/csv")
            
            c_del, c_rep = st.columns(2)
            with c_del:
                with st.expander("Delete Record"):
                    del_id = st.number_input("Report ID to Delete", 1)
                    if st.button("Confirm Delete"):
                        ok, msg = delete_record(del_id)
                        if ok: 
                            st.success(msg)
                            st.rerun()
                        else: st.error(msg)
            
            with c_rep:
                with st.expander("Regenerate Report"):
                    rep_id = st.number_input("Report ID", 1)
                    if st.button("Generate View"):
                        txt, stat = generate_report(rep_id)
                        if txt: st.download_button("Download", txt, f"Report_{rep_id}.txt")
                        else: st.error(stat)
        else:
            st.info("No records found in database.")

    # ---------------- TAB 3: IMPORT ----------------
    with tab_import:
        st.header("📂 Batch Import")
        
        # Template Generator
        st.markdown("#### 1. Download Template")
        b = io.BytesIO()
        template_data = {
            'Patient Name': ['Example Patient'], 'MRN': ['12345'], 'Age': [30], 
            'Weight': [65], 'Height': [165], 'Weeks': [12], 'Panel': ['NIPT Standard'],
            'Reads': [10.5], 'Cff': [12.0], 'GC': [41.0], 'QS': [1.2], 
            'Unique': [80.0], 'Error': [0.2],
            'SCA Type': ['XX'], 'Z-XX': [0.0], 'Z-XY': [0.0]
        }
        for i in range(1, 23): template_data[f'Z-{i}'] = [0.0]
        
        with pd.ExcelWriter(b, engine='xlsxwriter') as writer:
            pd.DataFrame(template_data).to_excel(writer, index=False)
        
        st.download_button("📥 Get Excel Template", b.getvalue(), "NIPT_Template.xlsx")

        # Uploader
        st.markdown("#### 2. Upload Data")
        uploaded = st.file_uploader("Upload Excel File", type=['xlsx'])
        if uploaded and st.button("Run Batch Analysis"):
            try:
                df_in = pd.read_excel(uploaded)
                success, fail = 0, 0
                bar = st.progress(0)
                
                for idx, row in df_in.iterrows():
                    try:
                        # Map Fields
                        p_data = {
                            'name': row.get('Patient Name'), 'id': str(row.get('MRN')), 
                            'age': row.get('Age'), 'weight': row.get('Weight'), 
                            'height': row.get('Height'), 'bmi': 0, 
                            'weeks': row.get('Weeks'), 'notes': ''
                        }
                        
                        # Gather Z-scores
                        z_map = {i: row.get(f'Z-{i}', 0.0) for i in range(1, 23)}
                        z_map['XX'] = row.get('Z-XX', 0.0)
                        z_map['XY'] = row.get('Z-XY', 0.0)

                        # Run Logic
                        t21 = analyze_trisomy(z_map[21], "21")
                        t18 = analyze_trisomy(z_map[18], "18")
                        t13 = analyze_trisomy(z_map[13], "13")
                        sca = analyze_sca(row.get('SCA Type', 'XX'), z_map['XX'], z_map['XY'], row.get('Cff', 10))

                        # Check RATs
                        rats = []
                        is_rat_high = False
                        for ch, z in z_map.items():
                            if isinstance(ch, int) and ch not in [13, 18, 21]:
                                msg = analyze_rat(ch, z)
                                if "POSITIVE" in msg or "Ambiguous" in msg:
                                    is_rat_high = True
                                    rats.append(f"Chr {ch} (Z:{z}) -> {msg}")

                        # Risk Calc
                        flags = t21 + t18 + t13 + sca
                        pos = "POSITIVE" in flags
                        high = "High Risk" in flags or is_rat_high or "Re-library" in flags
                        
                        qc_s, qc_m, qc_a = check_qc_metrics(
                            row.get('Panel'), row.get('Reads'), row.get('Cff'), row.get('GC'), 
                            row.get('QS'), row.get('Unique'), row.get('Error'), pos or high
                        )
                        
                        final = "NEGATIVE"
                        if pos: final = "POSITIVE DETECTED"
                        elif high: final = "HIGH RISK (SEE ADVICE)"
                        if qc_s == "FAIL": final = "INVALID (QC FAIL)"

                        # Save
                        save_result(p_data, 
                                   {'panel': row.get('Panel'), 'qc_status': qc_s, 'qc_msgs': qc_m, 'qc_advice': qc_a},
                                   {'t21': t21, 't18': t18, 't13': t13, 'sca': sca, 'cnv_list': [], 'rat_list': rats, 'final': final},
                                   full_z=z_map)
                        success += 1
                    except Exception:
                        fail += 1
                    bar.progress((idx + 1) / len(df_in))
                
                st.success(f"Processed: {success} | Failed: {fail}")
            except Exception as e:
                st.error(f"File Error: {e}")

if __name__ == "__main__":
    main()