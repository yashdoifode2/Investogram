"""
Domain Intelligence Service - Uses free WHOIS and DNS APIs
"""

import whois
import dns.resolver
import logging
import requests
import re
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class DomainIntelligence:
    """Gather domain intelligence using free APIs"""
    
    def __init__(self, domain):
        self.domain = domain
        self.whois_data = None
        self.dns_data = {}
        self.security_data = {}
        self._query_whois()
        self._query_dns()
        self._query_security()
    
    def _query_whois(self):
        """Query WHOIS for domain information"""
        try:
            self.whois_data = whois.whois(self.domain)
        except Exception as e:
            logger.warning(f"WHOIS query failed for {self.domain}: {e}")
    
    def _query_dns(self):
        """Query DNS records"""
        record_types = ['A', 'MX', 'TXT', 'NS', 'CNAME']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.dns_data[record_type] = [str(r) for r in answers]
            except Exception:
                pass
    
    def _query_security(self):
        """Query security-related data using free APIs"""
        # Check VirusTotal (free tier)
        try:
            # Using VirusTotal public API (limited)
            vt_url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
            # Free tier doesn't require API key for basic info
            response = requests.get(vt_url, timeout=10)
            if response.status_code == 200:
                self.security_data['virustotal'] = response.json()
        except Exception as e:
            logger.warning(f"VirusTotal query failed: {e}")
        
        # Check if domain is blacklisted using free DNSBL
        try:
            # Query multiple DNSBLs
            dnsbls = [
                'zen.spamhaus.org',
                'bl.spamcop.net',
                'dnsbl.sorbs.net',
                'cbl.abuseat.org'
            ]
            blacklisted = []
            for dnsbl in dnsbls:
                try:
                    query = f"{self.domain}.{dnsbl}"
                    dns.resolver.resolve(query, 'A')
                    blacklisted.append(dnsbl)
                except:
                    pass
            self.security_data['blacklisted'] = blacklisted
        except Exception as e:
            logger.warning(f"DNSBL query failed: {e}")
    
    def analyze(self):
        """Perform comprehensive domain analysis"""
        result = {
            'domain': self.domain,
            'whois': self._parse_whois(),
            'dns': self.dns_data,
            'security': self.security_data,
            'age_years': 0,
            'is_suspicious': False,
            'is_blacklisted': False,
            'tld': self._get_tld(),
            'registrar': None,
            'registration_date': None,
            'expiry_date': None,
            'blacklist_checks': [],
        }
        
        # Parse WHOIS data
        if self.whois_data:
            result['registrar'] = self._get_registrar()
            result['registration_date'] = self._get_registration_date()
            result['expiry_date'] = self._get_expiry_date()
            result['age_years'] = self._calculate_age()
        
        # Check blacklists
        if self.security_data.get('blacklisted'):
            result['is_blacklisted'] = True
            result['blacklist_checks'] = self.security_data['blacklisted']
        
        # Check for suspicious indicators
        result['is_suspicious'] = self._check_suspicious()
        
        return result
    
    def _parse_whois(self):
        """Parse WHOIS data"""
        if not self.whois_data:
            return {}
        
        data = {}
        for attr in dir(self.whois_data):
            if not attr.startswith('_'):
                try:
                    value = getattr(self.whois_data, attr)
                    if value and not callable(value):
                        data[attr] = str(value)
                except:
                    pass
        return data
    
    def _get_registrar(self):
        """Get registrar name"""
        if self.whois_data:
            return getattr(self.whois_data, 'registrar', 'Unknown')
        return 'Unknown'
    
    def _get_registration_date(self):
        """Get registration date"""
        if self.whois_data and self.whois_data.creation_date:
            if isinstance(self.whois_data.creation_date, list):
                return self.whois_data.creation_date[0].strftime('%Y-%m-%d')
            return self.whois_data.creation_date.strftime('%Y-%m-%d')
        return None
    
    def _get_expiry_date(self):
        """Get expiry date"""
        if self.whois_data and self.whois_data.expiration_date:
            if isinstance(self.whois_data.expiration_date, list):
                return self.whois_data.expiration_date[0].strftime('%Y-%m-%d')
            return self.whois_data.expiration_date.strftime('%Y-%m-%d')
        return None
    
    def _calculate_age(self):
        """Calculate domain age in years"""
        if self.whois_data and self.whois_data.creation_date:
            creation = self.whois_data.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            age = (datetime.now() - creation).days / 365
            return round(age, 1)
        return 0
    
    def _get_tld(self):
        """Get TLD from domain"""
        parts = self.domain.split('.')
        if len(parts) > 1:
            return parts[-1]
        return ''
    
    def _check_suspicious(self):
        """Check for suspicious domain indicators"""
        suspicious = False
        indicators = []
        
        # Check age
        if self._calculate_age() < 1:
            suspicious = True
            indicators.append('New domain (< 1 year)')
        
        # Check suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.cu', '.ir', '.su', '.ru', '.cn', '.top', '.xyz']
        if self._get_tld() in suspicious_tlds:
            suspicious = True
            indicators.append(f'Suspicious TLD: {self._get_tld()}')
        
        # Check for long domain
        if len(self.domain) > 50:
            suspicious = True
            indicators.append('Very long domain name')
        
        # Check for hyphens
        if '--' in self.domain:
            suspicious = True
            indicators.append('Contains multiple hyphens')
        
        # Check for numbers
        if re.search(r'\d{4,}', self.domain):
            suspicious = True
            indicators.append('Contains 4+ consecutive numbers')
        
        # Check blacklist
        if self.security_data.get('blacklisted'):
            suspicious = True
            indicators.append(f'Blacklisted on: {", ".join(self.security_data["blacklisted"])}')
        
        return suspicious