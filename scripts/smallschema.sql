-- schema.sql
-- Database initialization for Local NIPT Manager
-- Run this script to create the tables in 'nipt_data.db'

-- 1. Patients Table: Stores manual demographic inputs
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mrn_id TEXT UNIQUE NOT NULL,      -- Medical Record Number / Patient ID
    full_name TEXT NOT NULL,
    date_of_birth DATE,
    maternal_age INTEGER,             -- Age at time of test
    gestational_age_weeks INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. Results Table: Stores auto-parsed data from sequencing files
CREATE TABLE IF NOT EXISTS sample_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER,               -- Foreign key to patients table
    sample_barcode TEXT NOT NULL,     -- Links file to patient
    run_date DATE,
    
    -- Quality Control Data
    uniq_reads_millions REAL,         -- Mapped Reads 
    gc_ratio REAL,                    -- GC Content % 
    fetal_fraction REAL,              -- Cff % 
    quality_score REAL,               -- QS 
    qc_status TEXT,                   -- 'PASS' or 'FAIL'
    
    -- Analysis Data (Z-Scores)
    z_score_21 REAL,
    z_score_18 REAL,
    z_score_13 REAL,
    
    -- Final Interpretation
    clinical_report TEXT,             -- e.g., "Low Risk" or "High Risk"
    
    FOREIGN KEY(patient_id) REFERENCES patients(id)
);
