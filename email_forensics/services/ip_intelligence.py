"""
IP Intelligence Service - Uses free GeoIP and reputation APIs
"""

import requests
import logging
import socket
import ipaddress
from datetime import datetime

logger = logging.getLogger(__name__)

class IPIntelligence:
    """Gather IP intelligence using free APIs"""
    
    def __init__(self, ip_address):
        self.ip = ip_address
        self.geo_data = {}
        self.reputation_data = {}
        self._query_geo()
        self._query_reputation()
    
    def _query_geo(self):
        """Query geolocation using free APIs"""
        try:
            # ip-api.com - Free geolocation
            response = requests.get(f"http://ip-api.com/json/{self.ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    self.geo_data = {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                    }
        except Exception as e:
            logger.warning(f"GeoIP query failed: {e}")
        
        # Try ipinfo.io as fallback
        if not self.geo_data:
            try:
                response = requests.get(f"https://ipinfo.io/{self.ip}/json", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    self.geo_data = {
                        'country': data.get('country'),
                        'region': data.get('region'),
                        'city': data.get('city'),
                        'latitude': data.get('loc', '').split(',')[0] if data.get('loc') else None,
                        'longitude': data.get('loc', '').split(',')[1] if data.get('loc') else None,
                        'isp': data.get('org'),
                        'hostname': data.get('hostname'),
                    }
            except Exception as e:
                logger.warning(f"ipinfo.io query failed: {e}")
    
    def _query_reputation(self):
        """Query reputation using free APIs"""
        try:
            # AbuseIPDB free check
            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check",
                params={'ipAddress': self.ip, 'maxAgeInDays': '90'},
                headers={'Key': 'YOUR_ABUSEIPDB_KEY'},  # Optional: Add your key
                timeout=10
            )
            if response.status_code == 200:
                data = response.json().get('data', {})
                self.reputation_data = {
                    'abuse_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'reports': data.get('reports', [])[:5],
                    'is_blacklisted': data.get('abuseConfidenceScore', 0) > 30,
                    'country': data.get('countryCode'),
                }
        except Exception as e:
            logger.warning(f"AbuseIPDB query failed: {e}")
    
    def analyze(self):
        """Perform comprehensive IP analysis"""
        result = {
            'ip': self.ip,
            'geo': self.geo_data,
            'reputation': self.reputation_data,
            'is_private': ipaddress.ip_address(self.ip).is_private,
            'is_loopback': ipaddress.ip_address(self.ip).is_loopback,
            'is_multicast': ipaddress.ip_address(self.ip).is_multicast,
            'is_suspicious': False,
            'risk_score': 0,
            'risk_level': 'LOW',
            'hostname': None,
            'asn': None,
        }
        
        # Get hostname
        try:
            result['hostname'] = socket.gethostbyaddr(self.ip)[0]
        except:
            pass
        
        # Parse ASN from geo data
        if self.geo_data.get('as'):
            result['asn'] = self.geo_data['as']
        
        # Calculate risk score
        risk_score = 0
        
        # Private IP check
        if result['is_private']:
            risk_score += 10
        
        # AbuseIPDB score
        abuse_score = self.reputation_data.get('abuse_score', 0)
        if abuse_score > 0:
            risk_score += min(abuse_score / 10, 50)
        
        # Blacklist check
        if self.reputation_data.get('is_blacklisted', False):
            risk_score += 30
        
        # Unknown country
        if not self.geo_data.get('country'):
            risk_score += 10
        
        result['risk_score'] = min(risk_score, 100)
        result['risk_level'] = self._get_risk_level(result['risk_score'])
        result['is_suspicious'] = result['risk_score'] > 40
        
        return result
    
    def _get_risk_level(self, score):
        """Get risk level from score"""
        if score <= 25:
            return 'LOW'
        elif score <= 50:
            return 'MEDIUM'
        elif score <= 75:
            return 'HIGH'
        else:
            return 'CRITICAL'