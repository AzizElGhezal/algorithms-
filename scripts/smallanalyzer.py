# analyzer.py
from config import QC_RULES, Z_SCORE_CUTOFFS

class TrisomyAnalyzer:
    """
    Class to interpret NIPT Z-scores based on GeneMind logic.
    """
    
    def __init__(self, sample_data):
        # sample_data expects a dictionary: {'cff': 4.5, 'z_21': 1.2, ...}
        self.data = sample_data
        self.qc_passed = False
        self.qc_message = ""

    def check_hard_qc(self):
        """
        Validates sample against Hard QC rules .
        Returns True if PASS, False if FAIL.
        """
        cff = self.data.get('cff')
        gc = self.data.get('gc_ratio')
        
        # Check Fetal Fraction (Must be >= 3.5%)
        if cff < QC_RULES['MIN_CFF_PERCENT']:
            self.qc_message = f"FAIL: Fetal Fraction {cff}% is too low (<3.5%)"
            return False
            
        # Check GC Ratio (Must be 37-44%)
        if not (QC_RULES['GC_RATIO_MIN'] <= gc <= QC_RULES['GC_RATIO_MAX']):
            self.qc_message = f"FAIL: GC Ratio {gc}% out of range"
            return False
            
        # TODO: Add check for Quality Score (QS) logic here later
        
        self.qc_passed = True
        self.qc_message = "PASS"
        return True

    def interpret_risk(self, z_score):
        """
        Applies the decision tree from User Guide Section 2.2 .
        """
        # Define readable breakpoints for logic
        limit_low = Z_SCORE_CUTOFFS['LOW_RISK']       # 2.58
        ambig_low = Z_SCORE_CUTOFFS['AMBIGUOUS_LOW']  # 3.0
        ambig_high = Z_SCORE_CUTOFFS['AMBIGUOUS_HIGH']# 4.0
        limit_high = Z_SCORE_CUTOFFS['HIGH_RISK']     # 6.0

        if z_score < limit_low:
            return "Low Risk (Negative)"
            
        elif limit_low <= z_score < ambig_low:
            return "Low Risk - Ambiguous (Advice: Re-library)"
            
        elif ambig_low <= z_score < ambig_high:
            return "High Risk - Ambiguous (Advice: Resample)"
            
        elif ambig_high <= z_score < limit_high:
            return "High Risk (Advice: Resample/Verify)"
            
        else: # z_score >= 6.0
            return "High Risk (Positive)"

    def run_analysis(self):
        """
        Main function to execute QC and Z-score analysis.
        """
        # Step 1: Run QC
        if not self.check_hard_qc():
            return {
                "status": "INVALID",
                "reason": self.qc_message
            }

        # Step 2: Analyze Chromosomes 21, 18, 13
        results = {}
        for chrom in ['21', '18', '13']:
            z_val = self.data.get(f'z_{chrom}', 0.0)
            interpretation = self.interpret_risk(z_val)
            results[f'Chr{chrom}'] = {
                "Z-Score": z_val,
                "Result": interpretation
            }
            
        return {"status": "VALID", "results": results}
