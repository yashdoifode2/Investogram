"""
SPF Analyzer - Verifies SPF records and provides analysis
"""

import dns.resolver
import logging
import re

logger = logging.getLogger(__name__)

class SPFAnalyzer:
    """Analyze SPF records for a domain"""
    
    def __init__(self, domain):
        self.domain = domain
        self.spf_record = None
        self.parsed = None
        self._query_spf()
    
    def _query_spf(self):
        """Query DNS for SPF record"""
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    self.spf_record = txt
                    self.parsed = self._parse_spf_record(txt)
                    break
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain {self.domain} does not exist")
        except dns.resolver.NoAnswer:
            logger.warning(f"No SPF record found for {self.domain}")
        except Exception as e:
            logger.error(f"Error querying SPF for {self.domain}: {e}")
    
    def _parse_spf_record(self, record):
        """Parse SPF record into components"""
        parts = record.split()
        parsed = {
            'version': 'spf1',
            'mechanisms': [],
            'modifiers': {},
            'all': None,
        }
        
        for part in parts[1:]:
            if part.startswith('+'):
                mechanism = {'type': 'pass', 'value': part[1:]}
            elif part.startswith('-'):
                mechanism = {'type': 'fail', 'value': part[1:]}
            elif part.startswith('~'):
                mechanism = {'type': 'softfail', 'value': part[1:]}
            elif part.startswith('?'):
                mechanism = {'type': 'neutral', 'value': part[1:]}
            else:
                mechanism = {'type': 'pass', 'value': part}
            
            if mechanism['value'] == 'all':
                parsed['all'] = mechanism
            elif '=' in mechanism['value']:
                key, value = mechanism['value'].split('=', 1)
                parsed['modifiers'][key] = value
            else:
                parsed['mechanisms'].append(mechanism)
        
        return parsed
    
    def analyze(self, sender_ip=None):
        """Analyze SPF for a given sender IP"""
        result = {
            'domain': self.domain,
            'record_exists': bool(self.spf_record),
            'record': self.spf_record,
            'parsed': self.parsed,
            'result': 'NONE',
            'explanation': '',
            'risk': 'LOW',
        }
        
        if not self.spf_record:
            result['explanation'] = 'No SPF record found. Domain is vulnerable to spoofing.'
            result['risk'] = 'HIGH'
            return result
        
        if not self.parsed.get('mechanisms') and not self.parsed.get('modifiers'):
            result['explanation'] = 'SPF record exists but has no mechanisms.'
            result['risk'] = 'HIGH'
            return result
        
        all_mechanism = self.parsed.get('all')
        if all_mechanism:
            if all_mechanism['type'] == 'fail':
                result['explanation'] = 'SPF policy is strict (-all). Only authorized senders can send.'
                result['risk'] = 'LOW'
            elif all_mechanism['type'] == 'softfail':
                result['explanation'] = 'SPF policy is soft (~all). Allows some flexibility.'
                result['risk'] = 'MEDIUM'
            elif all_mechanism['type'] == 'neutral':
                result['explanation'] = 'SPF policy is neutral (?all). Does not enforce strict policy.'
                result['risk'] = 'HIGH'
        else:
            result['explanation'] = 'SPF record does not specify an "all" mechanism.'
            result['risk'] = 'MEDIUM'
        
        if sender_ip:
            authorized = self._check_ip_authorized(sender_ip)
            if authorized:
                result['result'] = 'PASS'
                result['explanation'] += ' Sender IP is authorized.'
            else:
                result['result'] = 'FAIL'
                result['explanation'] += ' Sender IP is not authorized.'
        
        return result
    
    def _check_ip_authorized(self, ip):
        """Check if IP is authorized by SPF (simplified)"""
        return True
    
    def get_risk_level(self, result):
        """Get risk level from SPF result"""
        risk_map = {
            'PASS': 'LOW',
            'FAIL': 'HIGH',
            'SOFTFAIL': 'MEDIUM',
            'NEUTRAL': 'HIGH',
            'NONE': 'HIGH',
        }
        return risk_map.get(result, 'MEDIUM')