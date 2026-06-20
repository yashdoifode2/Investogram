"""
Email Header Analyzer - Parses and analyzes email headers
"""

import re
from datetime import datetime
import logging
import socket
import ipaddress

logger = logging.getLogger(__name__)

class HeaderAnalyzer:
    """Analyze email headers for forensic insights"""
    
    def __init__(self, headers):
        self.headers = headers
        self.received_headers = self._parse_received_headers()
    
    def _parse_received_headers(self):
        """Parse all Received headers"""
        received = self.headers.get('received', [])
        if isinstance(received, str):
            received = [received]
        elif not isinstance(received, list):
            received = []
        
        parsed = []
        for header in received:
            parsed.append(self._parse_received_header(header))
        
        return parsed
    
    def _parse_received_header(self, header):
        """Parse a single Received header"""
        result = {
            'raw': header,
            'from': None,
            'by': None,
            'via': None,
            'with': None,
            'id': None,
            'for': None,
            'timestamp': None,
            'ip': None,
            'hostname': None,
        }
        
        # Extract timestamp
        timestamp_pattern = r';\s*(.+)$'
        timestamp_match = re.search(timestamp_pattern, header)
        if timestamp_match:
            try:
                timestamp_str = timestamp_match.group(1).strip()
                # Try different datetime formats
                for fmt in ['%a, %d %b %Y %H:%M:%S %z', '%a, %d %b %Y %H:%M:%S %Z', '%a, %d %b %Y %H:%M:%S']:
                    try:
                        result['timestamp'] = datetime.strptime(timestamp_str, fmt)
                        break
                    except:
                        continue
            except:
                pass
        
        # Extract from domain
        from_match = re.search(r'from\s+([^\s]+)\s+\(([^)]+)\)', header)
        if from_match:
            result['from'] = from_match.group(1)
            host_info = from_match.group(2)
            # Extract IP from host info
            ip_match = re.search(r'\[([\d.]+)\]', host_info)
            if ip_match:
                result['ip'] = ip_match.group(1)
            elif re.match(r'[\d.]+', host_info):
                result['ip'] = host_info
        
        # Extract by domain
        by_match = re.search(r'by\s+([^\s;]+)', header)
        if by_match:
            result['by'] = by_match.group(1)
        
        # Extract via
        via_match = re.search(r'via\s+([^\s;]+)', header)
        if via_match:
            result['via'] = via_match.group(1)
        
        # Extract with
        with_match = re.search(r'with\s+([^\s;]+)', header)
        if with_match:
            result['with'] = with_match.group(1)
        
        # Extract id
        id_match = re.search(r'id\s+([^\s;]+)', header)
        if id_match:
            result['id'] = id_match.group(1)
        
        # Extract for
        for_match = re.search(r'for\s+([^;]+)', header)
        if for_match:
            result['for'] = for_match.group(1).strip()
        
        # Extract hostname from from field
        if result['from'] and not result['ip']:
            try:
                ip = socket.gethostbyname(result['from'])
                if ip:
                    result['ip'] = ip
            except:
                pass
        
        return result
    
    def get_route_timeline(self):
        """Build route timeline from Received headers"""
        timeline = []
        for received in self.received_headers:
            entry = {
                'from': received.get('from'),
                'from_ip': received.get('ip'),
                'by': received.get('by'),
                'timestamp': received.get('timestamp'),
                'via': received.get('via'),
                'with': received.get('with'),
                'raw': received.get('raw'),
            }
            timeline.append(entry)
        
        return timeline
    
    def get_origin_ip(self):
        """Get origin IP from earliest Received header"""
        if self.received_headers:
            earliest = self.received_headers[-1]
            return earliest.get('ip')
        return None
    
    def get_destination_ip(self):
        """Get destination IP from latest Received header"""
        if self.received_headers:
            latest = self.received_headers[0]
            return latest.get('ip')
        return None
    
    def get_all_ips(self):
        """Extract all IPs from headers"""
        ips = []
        for received in self.received_headers:
            if received.get('ip'):
                ips.append(received['ip'])
        return list(set(ips))
    
    def analyze_authentication(self):
        """Analyze authentication results"""
        auth_results = self.headers.get('authentication-results', '')
        dkim_signature = self.headers.get('dkim-signature', '')
        
        result = {
            'auth_results': auth_results,
            'dkim_signature': dkim_signature,
            'spf': self._parse_spf(auth_results),
            'dkim': self._parse_dkim(auth_results),
            'dmarc': self._parse_dmarc(auth_results),
        }
        
        return result
    
    def _parse_spf(self, auth_results):
        """Parse SPF from authentication results"""
        spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        if spf_match:
            return spf_match.group(1).upper()
        return 'NONE'
    
    def _parse_dkim(self, auth_results):
        """Parse DKIM from authentication results"""
        dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
        if dkim_match:
            return dkim_match.group(1).upper()
        return 'NONE'
    
    def _parse_dmarc(self, auth_results):
        """Parse DMARC from authentication results"""
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
        if dmarc_match:
            return dmarc_match.group(1).upper()
        return 'NONE'