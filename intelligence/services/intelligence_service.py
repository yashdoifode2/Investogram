"""
Intelligence Service - Multi-provider
Automatically falls back to free APIs if IPQS fails
"""

import logging
from django.conf import settings
from .ipqs_service import IPQualityScoreService
from .free_apis_service import FreeAPIService

logger = logging.getLogger(__name__)

class IntelligenceService:
    """
    Main intelligence service that tries IPQS first, then falls back to free APIs
    """
    
    def __init__(self, user=None):
        self.user = user
        self.use_ipqs = settings.IPQS_ENABLED and settings.IPQS_API_KEY
        self.ipqs_service = IPQualityScoreService(user=user) if self.use_ipqs else None
        self.free_service = FreeAPIService(user=user)
        self.last_used = None
    
    def _try_ipqs(self, method, *args, **kwargs):
        """Try IPQS service, return None if fails"""
        if not self.ipqs_service:
            return None
        
        try:
            result = getattr(self.ipqs_service, method)(*args, **kwargs)
            if result and not result.get('error'):
                self.last_used = 'IPQS'
                return result
            return None
        except Exception as e:
            logger.warning(f"IPQS {method} failed: {e}")
            return None
    
    def _try_free_apis(self, method, *args, **kwargs):
        """Try free APIs service"""
        try:
            result = getattr(self.free_service, method)(*args, **kwargs)
            if result:
                self.last_used = 'Free APIs'
                return result
            return None
        except Exception as e:
            logger.warning(f"Free APIs {method} failed: {e}")
            return None
    
    def ip_lookup(self, ip_address, strictness=0, fast=False):
        """IP intelligence with fallback"""
        # Try IPQS first
        result = self._try_ipqs('ip_lookup', ip_address, strictness, fast)
        if result:
            result['source'] = 'IPQualityScore (Paid)'
            return result
        
        # Fallback to free APIs
        result = self._try_free_apis('ip_lookup', ip_address)
        if result:
            result['source'] = 'Free APIs (Open Source)'
            result['is_fallback'] = True
            return result
        
        # Return error if both fail
        return {
            'query': ip_address,
            'timestamp': datetime.now().isoformat(),
            'error': True,
            'message': 'Unable to fetch IP intelligence. Please check your connection.',
            'source': 'None'
        }
    
    def email_lookup(self, email):
        """Email intelligence with fallback"""
        result = self._try_ipqs('email_lookup', email)
        if result:
            result['source'] = 'IPQualityScore (Paid)'
            return result
        
        result = self._try_free_apis('email_lookup', email)
        if result:
            result['source'] = 'Free APIs (Open Source)'
            result['is_fallback'] = True
            return result
        
        return {
            'query': email,
            'timestamp': datetime.now().isoformat(),
            'error': True,
            'message': 'Unable to fetch email intelligence. Please check your connection.',
            'source': 'None'
        }
    
    def phone_lookup(self, phone_number, country_code=None):
        """Phone intelligence with fallback"""
        result = self._try_ipqs('phone_lookup', phone_number, country_code)
        if result:
            result['source'] = 'IPQualityScore (Paid)'
            return result
        
        result = self._try_free_apis('phone_lookup', phone_number, country_code)
        if result:
            result['source'] = 'Free APIs (Open Source)'
            result['is_fallback'] = True
            return result
        
        return {
            'query': phone_number,
            'timestamp': datetime.now().isoformat(),
            'error': True,
            'message': 'Unable to fetch phone intelligence. Please check your connection.',
            'source': 'None'
        }
    
    def url_lookup(self, url):
        """URL intelligence with fallback"""
        result = self._try_ipqs('url_lookup', url)
        if result:
            result['source'] = 'IPQualityScore (Paid)'
            return result
        
        result = self._try_free_apis('url_lookup', url)
        if result:
            result['source'] = 'Free APIs (Open Source)'
            result['is_fallback'] = True
            return result
        
        return {
            'query': url,
            'timestamp': datetime.now().isoformat(),
            'error': True,
            'message': 'Unable to fetch URL intelligence. Please check your connection.',
            'source': 'None'
        }
    
    def breach_lookup(self, email=None, username=None, phone=None):
        """Breach intelligence with fallback"""
        result = self._try_ipqs('breach_lookup', email, username, phone)
        if result:
            result['source'] = 'IPQualityScore (Paid)'
            return result
        
        result = self._try_free_apis('breach_lookup', email, username, phone)
        if result:
            result['source'] = 'Free APIs (Open Source)'
            result['is_fallback'] = True
            return result
        
        return {
            'query': email or username or phone,
            'timestamp': datetime.now().isoformat(),
            'error': True,
            'message': 'Unable to fetch breach intelligence. Please check your connection.',
            'source': 'None'
        }
    
    def test_connection(self):
        """Test connection with fallback"""
        # Try IPQS first
        if self.ipqs_service:
            try:
                result = self.ipqs_service.test_connection()
                if result and result.get('success'):
                    return result
            except Exception:
                pass
        
        # Fallback to free APIs
        return self.free_service.test_connection()