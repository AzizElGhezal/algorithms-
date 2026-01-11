# NRIS - NIPT Result Interpretation Software

**Version 2.0 Enhanced Edition**
*Advanced Clinical Genetics Dashboard with Authentication, Analytics & Reporting*

---

## 📋 Overview

NRIS (NIPT Result Interpretation Software) is a comprehensive web-based clinical genetics dashboard designed for managing and interpreting Non-Invasive Prenatal Testing (NIPT) results. This enhanced edition provides healthcare professionals with powerful tools for patient management, quality control analysis, clinical interpretation, and automated reporting.

### Key Features

- **🔐 User Authentication & Role-Based Access Control**
  - Secure login system with password hashing
  - Role-based permissions (Admin, Geneticist, Technician)
  - Session management and audit logging

- **👥 Patient Management**
  - Complete patient demographics and clinical history
  - MRN (Medical Record Number) tracking
  - BMI calculations and gestational age tracking
  - Comprehensive clinical notes

- **🧬 NIPT Result Analysis**
  - Multiple panel types (Basic, Standard, Plus, Pro)
  - Quality control metrics validation
  - Automated trisomy risk assessment (T13, T18, T21)
  - Sex chromosome anelploidy (SCA) detection
  - Rare autosomal trisomy (RAT) analysis
  - Fetal sex determination

- **📊 Advanced Analytics & Visualizations**
  - Interactive dashboards with Plotly
  - QC metrics trending and statistics
  - Result distribution analysis
  - Panel utilization reports

- **📄 Automated PDF Reporting**
  - Professional clinical reports with customizable headers
  - QC metrics summary and interpretation
  - Clinical recommendations based on thresholds
  - Digital signatures and timestamps

- **🔍 Audit Trail & Compliance**
  - Complete user activity logging
  - Result modification tracking
  - Export capabilities for compliance reviews

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.8 or higher** ([Download Python](https://www.python.org/downloads/))
- Windows, macOS, or Linux
- 4GB RAM minimum (8GB recommended)
- Modern web browser (Chrome, Firefox, Edge, Safari)

### Installation

#### Windows Users (Recommended)

1. **Download or clone this repository**
   ```bash
   git clone https://github.com/AzizElGhezal/NRIS.git
   cd NRIS
   ```

2. **Run the launcher**
   - Double-click `start_NRIS_v2.bat`
   - The launcher will automatically:
     - Check for Python installation
     - Create an isolated virtual environment
     - Install all dependencies
     - Launch the application

3. **Access the application**
   - Your web browser will automatically open to `http://localhost:8501`

#### Manual Installation (All Platforms)

1. **Clone the repository**
   ```bash
   git clone https://github.com/AzizElGhezal/NRIS.git
   cd NRIS
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv_NRIS_v2
   ```

3. **Activate the virtual environment**
   - Windows: `venv_NRIS_v2\Scripts\activate`
   - macOS/Linux: `source venv_NRIS_v2/bin/activate`

4. **Install dependencies**
   ```bash
   pip install -r requirements_NRIS_v2.txt
   ```

5. **Launch the application**
   ```bash
   streamlit run NRIS_Enhanced.py
   ```

6. **Open your browser to** `http://localhost:8501`

---

## 🔑 Default Login Credentials

```
Username: admin
Password: admin123
```

**⚠️ IMPORTANT:** Change the default password immediately after first login for security!

---

## 📚 Usage Guide

### First-Time Setup

1. **Login** with default credentials
2. **Change Password** in Settings → User Management
3. **Configure QC Thresholds** in Settings (optional)
4. **Create User Accounts** for your team members
5. **Import Patient Data** or add patients manually

### Daily Workflow

1. **Add/Select Patient** from the Patient Management tab
2. **Enter NIPT Results** with QC metrics
3. **Review Automated Interpretation** and clinical recommendations
4. **Generate PDF Report** for clinical records
5. **Export Data** for analysis or compliance

### Analytics & Reporting

- **Dashboard Tab**: Real-time overview of recent results and statistics
- **Analytics Tab**: Detailed QC trends, result distribution, and panel usage
- **Audit Log Tab**: Complete activity tracking and compliance reporting
- **Export Features**: Excel, CSV, and JSON data export capabilities

---

## 🛠️ Technical Specifications

### Technology Stack

- **Framework**: Streamlit 1.28+
- **Database**: SQLite3
- **Visualization**: Plotly 5.17+
- **Reporting**: ReportLab 4.0+
- **Data Processing**: Pandas 2.0+
- **PDF Handling**: PyPDF2 3.0+

### File Structure

```
NRIS/
├── NRIS_Enhanced.py           # Main application
├── start_NRIS_v2.bat          # Windows launcher
├── requirements_NRIS_v2.txt   # Python dependencies
├── README.md                  # This file
├── nipt_registry_v2.db        # Database (auto-created)
└── nris_config.json           # Configuration (auto-created)
```

### Dependencies

```
streamlit>=1.28.0
pandas>=2.0.0
plotly>=5.17.0
reportlab>=4.0.0
openpyxl>=3.1.0
xlsxwriter>=3.1.0
PyPDF2>=3.0.0
```

---

## ⚙️ Configuration

### QC Thresholds

Default quality control thresholds can be customized in the Settings tab:

- **Cell-Free Fetal DNA (CFF)**: Minimum 3.5%
- **GC Content**: 37.0-44.0%
- **Unique Read Rate**: Minimum 68.0%
- **Error Rate**: Maximum 1.0%
- **Quality Score Limits**: Negative <1.7, Positive >2.0

### Clinical Interpretation Thresholds

- **Trisomy Low Risk**: <2.58
- **Trisomy Ambiguous**: 2.58-6.0
- **Trisomy High Risk**: >6.0
- **SCA Threshold**: >4.5
- **RAT Positive**: >8.0
- **RAT Ambiguous**: 4.5-8.0

### Panel Types

- **NIPT Basic**: 5M reads minimum
- **NIPT Standard**: 7M reads minimum
- **NIPT Plus**: 12M reads minimum
- **NIPT Pro**: 20M reads minimum

---

## 🔒 Security & Compliance

### Security Features

- Password hashing using industry-standard algorithms
- Session-based authentication
- Role-based access control (RBAC)
- Audit logging for all data modifications
- Secure database storage with parameterized queries

### Data Privacy

- Patient data stored locally in SQLite database
- No external data transmission
- HIPAA compliance considerations built-in
- Audit trail for regulatory compliance

### Backup Recommendations

Regularly backup the following files:
- `nipt_registry_v2.db` - Contains all patient and result data
- `nris_config.json` - Contains custom configuration settings

---

## 🐛 Troubleshooting

### Common Issues

**Application won't start**
- Ensure Python 3.8+ is installed and in PATH
- Try running `pip install -r requirements_NRIS_v2.txt` manually
- Check firewall settings for port 8501

**Database errors**
- Delete `nipt_registry_v2.db` to reset (warning: deletes all data)
- Ensure write permissions in the application directory

**Import errors**
- Verify all dependencies installed: `pip list`
- Update pip: `pip install --upgrade pip`
- Reinstall requirements: `pip install -r requirements_NRIS_v2.txt --force-reinstall`

**Browser won't open**
- Manually navigate to `http://localhost:8501`
- Try a different browser
- Check if port 8501 is already in use

---

## 📝 Version History

### Version 2.0 (Current)
- Added user authentication and role-based access control
- Implemented comprehensive audit logging
- Enhanced analytics dashboard with Plotly visualizations
- Added automated PDF report generation
- Improved QC validation and clinical interpretation
- Added configuration management system
- Enhanced data export capabilities (Excel, CSV, JSON)

---

## 👤 Author

**Aziz El Ghezal**

---

## 📄 License

This software is provided for clinical and research use. Please ensure compliance with local regulations regarding medical software and patient data handling.

---

## 🤝 Support & Contributing

For issues, feature requests, or contributions:
- Open an issue on the GitHub repository
- Contact the development team
- Review the audit logs for troubleshooting

---

## ⚠️ Disclaimer

This software is designed to assist healthcare professionals in interpreting NIPT results. Clinical decisions should always be made by qualified medical professionals considering all available clinical information. This tool does not replace professional medical judgment.

---

**NRIS v2.0 Enhanced Edition** - Advancing Clinical Genetics Through Technology
