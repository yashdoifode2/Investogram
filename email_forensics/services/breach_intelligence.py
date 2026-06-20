"""
Breach Intelligence - Uses Have I Been Pwned and other free APIs
"""

import requests
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class BreachIntelligence:
    """Check for data breaches using free APIs"""
    
    def __init__(self, email=None, username=None, phone=None):
        self.email = email
        self.username = username
        self.phone = phone
        self.breaches = []
        self._check_breaches()
    
    def _check_breaches(self):
        """Check for breaches using various free APIs"""
        
        # 1. Have I Been Pwned (for email)
        if self.email:
            self._check_hibp()
        
        # 2. IntelligenceX (free tier)
        if self.email or self.username:
            self._check_intelligencex()
        
        # 3. Firefox Monitor (uses HIBP)
        if self.email:
            self._check_firefox_monitor()
        
        # 4. BreachDirectory (free tier)
        if self.email:
            self._check_breachdirectory()
    
    def _check_hibp(self):
        """Check Have I Been Pwned"""
        try:
            # Use HIBP API (v3)
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{self.email}",
                headers={'hibp-api-key': ''},  # No key needed for basic requests
                timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                for breach in data:
                    self.breaches.append({
                        'source': 'Have I Been Pwned',
                        'breach_name': breach.get('Name'),
                        'date': breach.get('BreachDate'),
                        'severity': self._get_severity(breach),
                        'data_classes': breach.get('DataClasses', []),
                        'description': breach.get('Description', '')[:200],
                        'url': f"https://haveibeenpwned.com/PwnedWebsites#{breach.get('Name')}",
                        'is_sensitive': False
                    })
            elif response.status_code == 404:
                # No breaches found
                pass
        except Exception as e:
            logger.warning(f"HIBP check failed: {e}")
    
    def _check_intelligencex(self):
        """Check IntelligenceX (free tier)"""
        try:
            # IntelligenceX free API (limited)
            search_term = self.email or self.username
            response = requests.get(
                f"https://api.intelx.io/intelligent/search",
                params={'term': search_term, 'maxresults': 5},
                timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('total', 0) > 0:
                    self.breaches.append({
                        'source': 'IntelligenceX',
                        'breach_name': 'IntelligenceX Search Results',
                        'date': datetime.now().strftime('%Y-%m-%d'),
                        'severity': 'MEDIUM',
                        'data_classes': ['Email', 'Username'],
                        'description': f'Found {data.get("total", 0)} records in IntelligenceX database',
                        'url': f"https://intelx.io/?s={search_term}",
                        'is_sensitive': False
                    })
        except Exception as e:
            logger.warning(f"IntelligenceX check failed: {e}")
    
    def _check_firefox_monitor(self):
        """Check Firefox Monitor (uses HIBP)"""
        try:
            # Firefox Monitor API
            response = requests.get(
                f"https://monitor.firefox.com/api/v2/breaches",
                timeout=15
            )
            if response.status_code == 200:
                # Firefox Monitor uses HIBP data
                # We already have HIBP results
                pass
        except Exception as e:
            logger.warning(f"Firefox Monitor check failed: {e}")
    
    def _check_breachdirectory(self):
        """Check BreachDirectory (free tier)"""
        try:
            # BreachDirectory free API
            response = requests.get(
                f"https://breachdirectory.p.rapidapi.com/",
                params={'email': self.email},
                headers={'X-RapidAPI-Key': ''},  # Free tier requires key
                timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('found', False):
                    self.breaches.append({
                        'source': 'BreachDirectory',
                        'breach_name': 'BreachDirectory Search',
                        'date': datetime.now().strftime('%Y-%m-%d'),
                        'severity': 'HIGH',
                        'data_classes': ['Email', 'Password'],
                        'description': f'Email found in breach database',
                        'url': f"https://breachdirectory.org",
                        'is_sensitive': True
                    })
        except Exception as e:
            logger.warning(f"BreachDirectory check failed: {e}")
    
    def _get_severity(self, breach):
        """Get severity based on breach data"""
        data_classes = breach.get('DataClasses', [])
        sensitive_classes = ['Passwords', 'Credit Cards', 'Social Security', 'Bank']
        if any(cls in sensitive_classes for cls in data_classes):
            return 'HIGH'
        elif len(data_classes) > 3:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_breaches(self):
        """Get all breach findings"""
        return self.breaches
    
    def get_summary(self):
        """Get breach summary"""
        total = len(self.breaches)
        high_severity = len([b for b in self.breaches if b.get('severity') == 'HIGH'])
        
        return {
            'total_breaches': total,
            'has_breaches': total > 0,
            'high_severity_count': high_severity,
            'sources': list(set([b['source'] for b in self.breaches])),
            'risk_level': 'HIGH' if high_severity > 0 else 'MEDIUM' if total > 0 else 'LOW',
            'breaches': self.breaches
        }