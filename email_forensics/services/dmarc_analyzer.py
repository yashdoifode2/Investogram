"""
DMARC Analyzer - Analyzes DMARC policies
"""

import dns.resolver
import logging
import re

logger = logging.getLogger(__name__)

class DMARCAnalyzer:
    """Analyze DMARC policies for a domain"""
    
    def __init__(self, domain):
        self.domain = domain
        self.dmarc_record = None
        self.parsed = None
        self._query_dmarc()
    
    def _query_dmarc(self):
        """Query DNS for DMARC record"""
        dmarc_domain = f"_dmarc.{self.domain}"
        try:
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=DMARC1'):
                    self.dmarc_record = txt
                    self.parsed = self._parse_dmarc_record(txt)
                    break
        except dns.resolver.NXDOMAIN:
            logger.warning(f"DMARC record not found for {self.domain}")
        except dns.resolver.NoAnswer:
            logger.warning(f"No DMARC record found for {self.domain}")
        except Exception as e:
            logger.error(f"Error querying DMARC for {self.domain}: {e}")
    
    def _parse_dmarc_record(self, record):
        """Parse DMARC record into components"""
        parsed = {}
        for part in record.split(';'):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                parsed[key.strip()] = value.strip()
        return parsed
    
    def analyze(self):
        """Analyze DMARC policy"""
        result = {
            'domain': self.domain,
            'record_exists': bool(self.dmarc_record),
            'record': self.dmarc_record,
            'parsed': self.parsed,
            'policy': 'NONE',
            'subdomain_policy': 'NONE',
            'pct': 100,
            'risk': 'HIGH',
            'explanation': '',
            'recommendations': [],
        }
        
        if not self.dmarc_record:
            result['explanation'] = 'No DMARC record found. Domain is vulnerable to spoofing.'
            result['risk'] = 'HIGH'
            result['recommendations'] = [
                'Publish a DMARC record with policy "p=quarantine" initially',
                'Monitor DMARC reports',
                'Gradually move to "p=reject" policy'
            ]
            return result
        
        policy = self.parsed.get('p', 'none').upper()
        result['policy'] = policy
        
        subdomain_policy = self.parsed.get('sp', 'none').upper()
        result['subdomain_policy'] = subdomain_policy
        
        pct = int(self.parsed.get('pct', 100))
        result['pct'] = pct
        
        if policy == 'REJECT':
            result['risk'] = 'LOW'
            result['explanation'] = 'DMARC policy is "reject". Unauthorized emails are rejected.'
            result['recommendations'] = [
                'Maintain current policy',
                'Monitor DMARC reports regularly'
            ]
        elif policy == 'QUARANTINE':
            result['risk'] = 'MEDIUM'
            result['explanation'] = 'DMARC policy is "quarantine". Unauthorized emails go to spam.'
            result['recommendations'] = [
                'Monitor DMARC reports',
                'Consider moving to "p=reject" after monitoring'
            ]
        else:
            result['risk'] = 'HIGH'
            result['explanation'] = 'DMARC policy is "none". No enforcement against spoofing.'
            result['recommendations'] = [
                'Implement "p=quarantine" policy',
                'Monitor DMARC reports',
                'Gradually move to "p=reject"'
            ]
        
        return result
    
    def get_risk_level(self):
        """Get risk level from DMARC analysis"""
        if not self.dmarc_record:
            return 'HIGH'
        
        policy = self.parsed.get('p', 'none').upper()
        risk_map = {
            'REJECT': 'LOW',
            'QUARANTINE': 'MEDIUM',
            'NONE': 'HIGH',
        }
        return risk_map.get(policy, 'HIGH')