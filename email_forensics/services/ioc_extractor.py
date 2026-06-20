"""
IOC Extractor - Extracts Indicators of Compromise from emails
"""

import re
import hashlib
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class IOCExtractor:
    """Extract IOCs from email content"""
    
    def __init__(self, parsed_email):
        self.parsed_email = parsed_email
        self.iocs = []
    
    def extract_all(self):
        """Extract all types of IOCs"""
        self.extract_emails()
        self.extract_domains()
        self.extract_urls()
        self.extract_ips()
        self.extract_hashes()
        return self.iocs
    
    def extract_emails(self):
        """Extract email addresses"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        # Check headers
        for header in ['from', 'to', 'reply_to', 'return_path']:
            value = self.parsed_email.get(header, '')
            if value:
                matches = re.findall(email_pattern, value)
                for match in matches:
                    self._add_ioc('EMAIL', match, f'Header: {header}')
        
        # Check body
        body = self.parsed_email.get('body', '')
        matches = re.findall(email_pattern, body)
        for match in matches:
            self._add_ioc('EMAIL', match, 'Email body')
    
    def extract_domains(self):
        """Extract domains"""
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        
        # Check headers
        for header in ['from', 'reply_to']:
            value = self.parsed_email.get(header, '')
            if value:
                # Extract domain from email
                email_match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', value)
                if email_match:
                    self._add_ioc('DOMAIN', email_match.group(1), f'Header: {header}')
        
        # Extract from URLs
        for url in self.parsed_email.get('urls', []):
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain:
                    self._add_ioc('DOMAIN', domain, 'From URL')
            except:
                pass
        
        # Check body
        body = self.parsed_email.get('body', '')
        matches = re.findall(domain_pattern, body)
        for match in matches:
            if not match.startswith('www.') and '.' in match:
                self._add_ioc('DOMAIN', match, 'Email body')
    
    def extract_urls(self):
        """Extract URLs"""
        url_pattern = r'https?://[^\s<>"\'(){}|\\^`\[\]]+'
        
        # Check body
        body = self.parsed_email.get('body', '')
        matches = re.findall(url_pattern, body)
        for match in matches:
            self._add_ioc('URL', match, 'Email body')
        
        # Check HTML body
        html_body = self.parsed_email.get('html_body', '')
        matches = re.findall(url_pattern, html_body)
        for match in matches:
            self._add_ioc('URL', match, 'HTML body')
    
    def extract_ips(self):
        """Extract IP addresses"""
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        
        # Check headers
        received = self.parsed_email.get('received', [])
        for header in received:
            matches = re.findall(ipv4_pattern, str(header))
            for match in matches:
                self._add_ioc('IPV4', match, 'Received header')
        
        # Check body
        body = self.parsed_email.get('body', '')
        matches = re.findall(ipv4_pattern, body)
        for match in matches:
            self._add_ioc('IPV4', match, 'Email body')
        
        matches = re.findall(ipv6_pattern, body)
        for match in matches:
            self._add_ioc('IPV6', match, 'Email body')
    
    def extract_hashes(self):
        """Extract file hashes"""
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        
        body = self.parsed_email.get('body', '')
        
        # MD5
        matches = re.findall(md5_pattern, body)
        for match in matches:
            self._add_ioc('MD5', match, 'Email body')
        
        # SHA1
        matches = re.findall(sha1_pattern, body)
        for match in matches:
            self._add_ioc('SHA1', match, 'Email body')
        
        # SHA256
        matches = re.findall(sha256_pattern, body)
        for match in matches:
            self._add_ioc('SHA256', match, 'Email body')
    
    def _add_ioc(self, ioc_type, value, context=''):
        """Add IOC to list"""
        # Check if already exists
        for ioc in self.iocs:
            if ioc['type'] == ioc_type and ioc['value'] == value:
                if context and context not in ioc['context']:
                    ioc['context'] = f"{ioc['context']}; {context}"
                return
        
        self.iocs.append({
            'type': ioc_type,
            'value': value,
            'context': context,
        })