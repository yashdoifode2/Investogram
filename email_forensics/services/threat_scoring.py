"""
Threat Scoring Engine - Calculates risk scores for email analysis
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class ThreatScorer:
    """Calculate threat scores based on analysis findings"""
    
    def __init__(self, analysis):
        self.analysis = analysis
        self.score = 0
        self.indicators = []
    
    def calculate_score(self):
        """Calculate overall threat score"""
        self._score_spf()
        self._score_dkim()
        self._score_dmarc()
        self._score_headers()
        self._score_domain()
        self._score_iocs()
        self._score_attachments()
        self._score_breach()
        
        # Cap score at 100
        self.score = min(self.score, 100)
        
        # Determine risk level
        if self.score <= 25:
            level = 'LOW'
        elif self.score <= 50:
            level = 'MEDIUM'
        elif self.score <= 75:
            level = 'HIGH'
        else:
            level = 'CRITICAL'
        
        return {
            'score': self.score,
            'level': level,
            'indicators': self.indicators
        }
    
    def _score_spf(self):
        """Score SPF analysis"""
        spf = self.analysis.spf_result
        if spf:
            result = spf.get('result', 'NONE')
            if result == 'FAIL':
                self.score += 20
                self.indicators.append('SPF FAIL')
            elif result == 'SOFTFAIL':
                self.score += 10
                self.indicators.append('SPF SOFTFAIL')
            elif result == 'NONE':
                self.score += 15
                self.indicators.append('SPF NONE')
    
    def _score_dkim(self):
        """Score DKIM analysis"""
        dkim = self.analysis.dkim_result
        if dkim:
            if not dkim.get('valid', False):
                if dkim.get('error') == 'No DKIM signature found':
                    self.score += 15
                    self.indicators.append('DKIM Missing')
                elif dkim.get('error') == 'Public key not found in DNS':
                    self.score += 20
                    self.indicators.append('DKIM Invalid Key')
                else:
                    self.score += 15
                    self.indicators.append('DKIM Failed')
    
    def _score_dmarc(self):
        """Score DMARC analysis"""
        dmarc = self.analysis.dmarc_result
        if dmarc:
            policy = dmarc.get('policy', 'NONE')
            if policy == 'NONE':
                self.score += 15
                self.indicators.append('DMARC NONE')
            elif policy == 'QUARANTINE':
                self.score += 5
                self.indicators.append('DMARC QUARANTINE')
            elif not dmarc.get('record_exists', False):
                self.score += 20
                self.indicators.append('DMARC Missing')
    
    def _score_headers(self):
        """Score header analysis"""
        # Check for suspicious headers
        headers = self.analysis.headers
        if headers:
            # Check for missing authentication headers
            parsed = self.analysis.parsed_email
            if not parsed.get('authentication_results'):
                self.score += 10
                self.indicators.append('No Auth Results')
    
    def _score_domain(self):
        """Score domain intelligence"""
        domain_intel = self.analysis.domain_intelligence
        if domain_intel:
            # Check domain age
            age_years = domain_intel.get('age_years', 0)
            if age_years < 1:
                self.score += 10
                self.indicators.append('New Domain (< 1 year)')
            
            # Check for suspicious TLD
            tld = domain_intel.get('tld', '')
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.cu', '.ir', '.su']
            if tld in suspicious_tlds:
                self.score += 10
                self.indicators.append(f'Suspicious TLD: {tld}')
            
            # Check if domain is blacklisted
            if domain_intel.get('is_blacklisted', False):
                self.score += 15
                self.indicators.append('Domain Blacklisted')
    
    def _score_iocs(self):
        """Score IOCs"""
        iocs = self.analysis.ioc_objects.all()
        for ioc in iocs:
            if ioc.is_malicious:
                self.score += 5
                self.indicators.append(f'Malicious {ioc.get_ioc_type_display()}')
    
    def _score_attachments(self):
        """Score attachments"""
        attachments = self.analysis.attachment_findings
        for attachment in attachments:
            if attachment.get('is_suspicious', False):
                self.score += 15
                self.indicators.append(f'Suspicious Attachment: {attachment.get("filename")}')
            
            if attachment.get('has_macros', False):
                self.score += 20
                self.indicators.append('Macros in Attachment')
    
    def _score_breach(self):
        """Score breach exposure"""
        breach_data = self.analysis.breach_data
        if breach_data:
            for breach in breach_data:
                if breach.get('total_breaches', 0) > 0:
                    self.score += 10
                    self.indicators.append('Breach Exposure')
                    break