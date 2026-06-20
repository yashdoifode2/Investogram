import requests
import logging
import json
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

class IPQualityScoreService:
    """Service class for IPQualityScore API integration with user-specific keys"""
    
    def __init__(self, user=None):
        self.user = user
        self.api_key = self._get_user_api_key()
        self.base_url = settings.IPQS_BASE_URL
        self.timeout = settings.IPQS_TIMEOUT
        self.max_retries = settings.IPQS_MAX_RETRIES
        self.enabled = settings.IPQS_ENABLED
        
    def _get_user_api_key(self):
        """Get user-specific API key from core_settings"""
        if not self.user:
            return settings.IPQS_API_KEY
        
        try:
            from core_settings.models import APIService
            
            ipqs_service = APIService.objects.filter(
                user=self.user,
                service_type='IPQS',
                is_enabled=True
            ).first()
            
            if ipqs_service:
                decrypted_key = ipqs_service.get_decrypted_key()
                if decrypted_key:
                    logger.info(f"Using user-specific IPQS key for {self.user.username}")
                    return decrypted_key
            
            logger.warning(f"No user-specific IPQS key found for {self.user.username}, using global key")
            return settings.IPQS_API_KEY
            
        except Exception as e:
            logger.error(f"Error retrieving user API key: {e}")
            return settings.IPQS_API_KEY
    
    def _log_usage(self, endpoint, status, response_time, is_error=False, error_message=''):
        """Log API usage to database"""
        if not self.user:
            return
        
        try:
            from core_settings.models import APIUsageLog, APIService
            
            ipqs_service = APIService.objects.filter(
                user=self.user,
                service_type='IPQS'
            ).first()
            
            if ipqs_service:
                APIUsageLog.objects.create(
                    service=ipqs_service,
                    user=self.user,
                    endpoint=endpoint,
                    method='GET',
                    response_status=status,
                    response_time=response_time,
                    is_error=is_error,
                    error_message=error_message,
                    ip_address=None
                )
        except Exception as e:
            logger.error(f"Error logging API usage: {e}")
    
    def _log_audit(self, action, details, ip_address=None):
        """Log API audit events"""
        if not self.user:
            return
        
        try:
            from core_settings.models import APIAuditLog
            
            APIAuditLog.objects.create(
                user=self.user,
                action=action,
                details=details,
                ip_address=ip_address
            )
        except Exception as e:
            logger.error(f"Error logging audit: {e}")
    
    def _make_request(self, endpoint, params, method='GET'):
        """Make API request with retry logic and user-specific key"""
        if not self.enabled:
            raise ValueError("IPQS Integration is disabled")
        
        if not self.api_key:
            raise ValueError("API key not configured for this user")
        
        params['key'] = self.api_key
        url = f"{self.base_url}/{endpoint}"
        
        start_time = timezone.now()
        
        for attempt in range(self.max_retries):
            try:
                response = requests.request(
                    method,
                    url,
                    params=params if method == 'GET' else None,
                    json=params if method == 'POST' else None,
                    timeout=self.timeout
                )
                
                response_time = (timezone.now() - start_time).total_seconds()
                
                # Parse response
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    data = {'success': False, 'message': 'Invalid JSON response'}
                
                # Check if response indicates an error (even with 200 status)
                if data.get('success') is False or data.get('message') == 'Invalid or unauthorized key':
                    error_msg = data.get('message', 'Invalid or unauthorized key')
                    self._log_usage(
                        endpoint=endpoint,
                        status=response.status_code,
                        response_time=response_time,
                        is_error=True,
                        error_message=error_msg
                    )
                    self._log_audit('API_ERROR', {
                        'endpoint': endpoint,
                        'error': error_msg,
                        'status_code': response.status_code
                    })
                    raise ValueError(f"API Error: {error_msg}")
                
                # Check if response has success=False
                if data.get('success') is False:
                    error_msg = data.get('message', 'API request failed')
                    self._log_usage(
                        endpoint=endpoint,
                        status=response.status_code,
                        response_time=response_time,
                        is_error=True,
                        error_message=error_msg
                    )
                    raise ValueError(f"API Error: {error_msg}")
                
                # Log successful API call
                self._log_usage(
                    endpoint=endpoint,
                    status=response.status_code,
                    response_time=response_time,
                    is_error=False
                )
                
                self._log_audit('API_CALL', {
                    'endpoint': endpoint,
                    'status': response.status_code,
                    'response_time': response_time
                })
                
                return data
                
            except requests.exceptions.Timeout as e:
                response_time = (timezone.now() - start_time).total_seconds()
                logger.warning(f"Timeout on attempt {attempt + 1}/{self.max_retries}")
                if attempt == self.max_retries - 1:
                    self._log_usage(
                        endpoint=endpoint,
                        status=408,
                        response_time=response_time,
                        is_error=True,
                        error_message=str(e)
                    )
                    raise
            
            except requests.exceptions.RequestException as e:
                response_time = (timezone.now() - start_time).total_seconds()
                logger.warning(f"Request error on attempt {attempt + 1}: {e}")
                if attempt == self.max_retries - 1:
                    self._log_usage(
                        endpoint=endpoint,
                        status=getattr(e.response, 'status_code', 500),
                        response_time=response_time,
                        is_error=True,
                        error_message=str(e)
                    )
                    self._log_audit('API_ERROR', {
                        'endpoint': endpoint,
                        'error': str(e)
                    })
                    raise
                    
            except ValueError as e:
                # Re-raise ValueError (which contains API error messages)
                raise
                
            except Exception as e:
                response_time = (timezone.now() - start_time).total_seconds()
                logger.error(f"Unexpected error: {e}")
                self._log_usage(
                    endpoint=endpoint,
                    status=500,
                    response_time=response_time,
                    is_error=True,
                    error_message=str(e)
                )
                self._log_audit('API_ERROR', {
                    'endpoint': endpoint,
                    'error': str(e)
                })
                raise
        
        raise Exception("Max retries exceeded")
    
    def _parse_risk_score(self, data):
        """Parse risk score from API response"""
        fraud_score = data.get('fraud_score', 0)
        
        if fraud_score == 0:
            return 0
        elif fraud_score <= 25:
            return 2
        elif fraud_score <= 50:
            return 4
        elif fraud_score <= 75:
            return 6
        elif fraud_score <= 90:
            return 8
        else:
            return 10
    
    def _get_risk_level(self, score):
        """Convert risk score to risk level"""
        if score is None:
            return 'Unknown'
        
        score = int(score)
        if score == 0:
            return 'Low'
        elif score <= 25:
            return 'Low'
        elif score <= 50:
            return 'Medium'
        elif score <= 75:
            return 'High'
        elif score <= 90:
            return 'High'
        else:
            return 'Critical'
    
    # ============================================
    # LOOKUP METHODS
    # ============================================
    
    def ip_lookup(self, ip_address, strictness=0, fast=False):
        """Perform IP intelligence lookup with user's API key"""
        endpoint = f"ip/{ip_address}"
        params = {
            'strictness': strictness,
            'fast': 'true' if fast else 'false',
            'allow_public_access_points': 'true',
            'lighter_penalties': 'false',
            'mobile': 'false'
        }
        
        try:
            data = self._make_request(endpoint, params)
            
            result = {
                'query': ip_address,
                'timestamp': datetime.now().isoformat(),
                'network': {
                    'ip': data.get('ip_address'),
                    'asn': data.get('ASN'),
                    'isp': data.get('ISP'),
                    'organization': data.get('organization'),
                    'hostname': data.get('hostname'),
                },
                'geolocation': {
                    'country': data.get('country_name'),
                    'country_code': data.get('country_code'),
                    'region': data.get('region'),
                    'city': data.get('city'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'timezone': data.get('timezone'),
                },
                'security': {
                    'fraud_score': data.get('fraud_score'),
                    'risk_score': self._parse_risk_score(data),
                    'is_vpn': data.get('vpn'),
                    'is_proxy': data.get('proxy'),
                    'is_tor': data.get('tor'),
                    'is_bot': data.get('bot_status'),
                    'is_hosting': data.get('hosting_provider'),
                    'is_active_vpn': data.get('active_vpn'),
                    'abuse_velocity': data.get('abuse_velocity'),
                    'risk_level': self._get_risk_level(data.get('fraud_score', 0)),
                },
                'additional': {
                    'recent_abuse': data.get('recent_abuse'),
                    'is_crawler': data.get('is_crawler'),
                    'is_blacklisted': data.get('blacklisted'),
                    'is_mobile': data.get('mobile'),
                    'is_public_access_point': data.get('public_access_point'),
                },
                'raw_data': data
            }
            
            return result
            
        except Exception as e:
            logger.error(f"IP lookup failed for {ip_address}: {e}")
            raise
    
    def email_lookup(self, email):
        """Perform email intelligence lookup"""
        endpoint = f"email/{email}"
        params = {
            'strictness': 1,
            'abuse_strictness': 1,
        }
        
        try:
            data = self._make_request(endpoint, params)
            
            result = {
                'query': email,
                'timestamp': datetime.now().isoformat(),
                'validation': {
                    'valid': data.get('valid'),
                    'deliverable': data.get('deliverable'),
                    'catch_all': data.get('catch_all'),
                    'disposable': data.get('disposable'),
                    'free_provider': data.get('free_email_provider'),
                },
                'reputation': {
                    'fraud_score': data.get('fraud_score'),
                    'risk_score': self._parse_risk_score(data),
                    'spam_trap': data.get('spam_trap_score'),
                    'abuse_score': data.get('abuse_score'),
                    'recent_abuse': data.get('recent_abuse'),
                },
                'domain': {
                    'domain': data.get('domain'),
                    'domain_age': data.get('domain_age'),
                    'domain_rank': data.get('domain_rank'),
                    'domain_blacklisted': data.get('domain_blacklisted'),
                },
                'security': {
                    'risk_level': self._get_risk_level(data.get('fraud_score', 0)),
                    'is_risky': data.get('risky'),
                    'is_high_risk': data.get('high_risk'),
                },
                'additional': {
                    'first_seen': data.get('first_seen'),
                    'last_seen': data.get('last_seen'),
                    'suspicious_tld': data.get('suspicious_tld'),
                },
                'raw_data': data
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Email lookup failed for {email}: {e}")
            raise
    
    def phone_lookup(self, phone_number, country_code=None):
        """Perform phone intelligence lookup"""
        endpoint = f"phone"
        params = {
            'phone': phone_number,
            'country_code': country_code or 'auto',
        }
        
        try:
            data = self._make_request(endpoint, params)
            
            result = {
                'query': phone_number,
                'timestamp': datetime.now().isoformat(),
                'basic': {
                    'valid': data.get('valid'),
                    'country': data.get('country'),
                    'country_code': data.get('country_code'),
                    'carrier': data.get('carrier'),
                    'number_type': data.get('line_type'),
                    'local_format': data.get('local_format'),
                    'international_format': data.get('international_format'),
                },
                'risk': {
                    'fraud_score': data.get('fraud_score'),
                    'risk_score': self._parse_risk_score(data),
                    'risk_level': self._get_risk_level(data.get('fraud_score', 0)),
                    'prepaid': data.get('prepaid'),
                    'mobile': data.get('mobile'),
                    'active': data.get('active'),
                },
                'additional': {
                    'recent_abuse': data.get('recent_abuse'),
                    'is_risky': data.get('risky'),
                },
                'raw_data': data
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Phone lookup failed for {phone_number}: {e}")
            raise
    
    def url_lookup(self, url):
        """Perform URL/Domain intelligence lookup"""
        endpoint = f"url"
        params = {
            'url': url,
            'strictness': 1,
            'fast': 'false',
        }
        
        try:
            data = self._make_request(endpoint, params)
            
            result = {
                'query': url,
                'timestamp': datetime.now().isoformat(),
                'reputation': {
                    'unsafe': data.get('unsafe'),
                    'risk_score': data.get('risk_score'),
                    'risk_level': self._get_risk_level(data.get('risk_score', 0)),
                    'domain': data.get('domain'),
                    'server': data.get('server'),
                },
                'threat': {
                    'phishing': data.get('phishing'),
                    'malware': data.get('malware'),
                    'parked_domain': data.get('parked_domain'),
                    'suspicious': data.get('suspicious'),
                    'virus_total_score': data.get('virus_total_score'),
                },
                'category': {
                    'category': data.get('category'),
                    'category_code': data.get('category_code'),
                },
                'additional': {
                    'url': data.get('url'),
                    'ip_address': data.get('ip_address'),
                    'status_code': data.get('status_code'),
                    'redirect_url': data.get('redirect_url'),
                },
                'raw_data': data
            }
            
            return result
            
        except Exception as e:
            logger.error(f"URL lookup failed for {url}: {e}")
            raise
    
    def breach_lookup(self, email=None, username=None, phone=None):
        """Perform breach intelligence lookup"""
        endpoint = f"breach"
        params = {}
        
        if email:
            params['email'] = email
        elif username:
            params['username'] = username
        elif phone:
            params['phone'] = phone
        else:
            raise ValueError("Email, username, or phone is required")
        
        try:
            data = self._make_request(endpoint, params)
            
            if data.get('success') is False:
                return {
                    'query': email or username or phone,
                    'timestamp': datetime.now().isoformat(),
                    'supported': False,
                    'message': 'Breach intelligence not available on current API plan',
                    'breaches': [],
                    'total_breaches': 0,
                    'risk_level': 'Unknown'
                }
            
            breaches = data.get('breaches', [])
            
            result = {
                'query': email or username or phone,
                'timestamp': datetime.now().isoformat(),
                'supported': True,
                'breaches': breaches,
                'total_breaches': len(breaches),
                'risk_level': 'High' if len(breaches) > 0 else 'Low',
                'sources': list(set([b.get('source', 'Unknown') for b in breaches])),
                'raw_data': data
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Breach lookup failed: {e}")
            raise
    
    # ============================================
    # TEST CONNECTION METHOD - FIXED
    # ============================================
    
    def test_connection(self):
        """
        Test API connectivity with user's API key
        Properly handles the response to detect invalid keys
        """
        try:
            # Use a well-known IP for testing
            test_ip = '8.8.8.8'
            
            # Make a simple request with minimal parameters
            endpoint = f"ip/{test_ip}"
            params = {
                'strictness': 0,
                'fast': 'true',
                'allow_public_access_points': 'true'
            }
            
            # Try to make the request
            data = self._make_request(endpoint, params)
            
            # Check if we got a valid response
            if data and data.get('success') is not False:
                # Check if we got IP data
                if data.get('ip_address') or data.get('fraud_score') is not None:
                    return {
                        'success': True,
                        'message': 'API connection successful ✅',
                        'api_key_valid': True,
                        'rate_limit_remaining': data.get('quota_remaining', 1000),
                        'data': data
                    }
                else:
                    return {
                        'success': False,
                        'message': 'Invalid response from API',
                        'api_key_valid': False
                    }
            else:
                error_msg = data.get('message', 'Invalid or unauthorized key')
                return {
                    'success': False,
                    'message': f'❌ Invalid or unauthorized key. {error_msg}',
                    'api_key_valid': False
                }
                
        except ValueError as e:
            # This catches the API error messages
            error_msg = str(e).replace('API Error: ', '')
            return {
                'success': False,
                'message': f'❌ {error_msg}',
                'api_key_valid': False
            }
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                return {
                    'success': False,
                    'message': '❌ Invalid or unauthorized key. Please check your API key.',
                    'api_key_valid': False
                }
            elif e.response.status_code == 429:
                return {
                    'success': False,
                    'message': '❌ Rate limit exceeded. Please try again later.',
                    'api_key_valid': True
                }
            else:
                return {
                    'success': False,
                    'message': f'❌ HTTP Error {e.response.status_code}: {str(e)}',
                    'api_key_valid': False
                }
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'message': '❌ Connection timeout. Please check your network.',
                'api_key_valid': False
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'message': '❌ Connection error. Please check your network.',
                'api_key_valid': False
            }
        except Exception as e:
            logger.error(f"API test failed: {e}")
            return {
                'success': False,
                'message': f'❌ Error: {str(e)}',
                'api_key_valid': False
            }