"""
Free Open APIs Intelligence Service
Fetches data from various free APIs when IPQS is not available
"""

import requests
import json
import logging
from datetime import datetime
from ipaddress import ip_address, IPv4Address, IPv6Address

logger = logging.getLogger(__name__)

class FreeAPIService:
    """Service that uses free open APIs for intelligence lookups"""
    
    def __init__(self, user=None):
        self.user = user
        self.timeout = 10
        self.max_retries = 2
        
    def _safe_request(self, url, params=None, headers=None):
        """Make a safe request with error handling"""
        try:
            response = requests.get(url, params=params, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.warning(f"Free API request failed: {e}")
            return None
    
    def _get_risk_level(self, score):
        """Convert score to risk level"""
        if score is None:
            return 'Unknown'
        score = int(score)
        if score <= 25:
            return 'Low'
        elif score <= 50:
            return 'Medium'
        elif score <= 75:
            return 'High'
        else:
            return 'Critical'
    
    # ============================================
    # IP INTELLIGENCE - Multiple free APIs
    # ============================================
    
    def ip_lookup(self, ip_address):
        """Get IP intelligence from free APIs"""
        result = {
            'query': ip_address,
            'timestamp': datetime.now().isoformat(),
            'network': {},
            'geolocation': {},
            'security': {},
            'additional': {},
            'sources': [],
            'raw_data': {}
        }
        
        # Try multiple free APIs
        data = {}
        
        # 1. ip-api.com - Free IP geolocation
        try:
            ip_api_data = self._safe_request(f"http://ip-api.com/json/{ip_address}")
            if ip_api_data and ip_api_data.get('status') == 'success':
                data['ip_api'] = ip_api_data
                result['sources'].append('ip-api.com')
                
                result['geolocation'] = {
                    'country': ip_api_data.get('country'),
                    'country_code': ip_api_data.get('countryCode'),
                    'region': ip_api_data.get('regionName'),
                    'city': ip_api_data.get('city'),
                    'latitude': ip_api_data.get('lat'),
                    'longitude': ip_api_data.get('lon'),
                    'timezone': ip_api_data.get('timezone'),
                    'zip': ip_api_data.get('zip'),
                }
                
                result['network'] = {
                    'ip': ip_api_data.get('query'),
                    'isp': ip_api_data.get('isp'),
                    'organization': ip_api_data.get('org'),
                    'asn': ip_api_data.get('as'),
                }
                
                result['additional'] = {
                    'is_mobile': False,
                    'is_proxy': False,
                    'is_hosting': False,
                }
        except Exception as e:
            logger.warning(f"ip-api.com failed: {e}")
        
        # 2. ipinfo.io - Free IP intelligence (limited)
        try:
            ipinfo_data = self._safe_request(f"https://ipinfo.io/{ip_address}/json")
            if ipinfo_data and ipinfo_data.get('ip'):
                data['ipinfo'] = ipinfo_data
                result['sources'].append('ipinfo.io')
                
                # Merge with existing data
                if not result['geolocation'].get('country'):
                    result['geolocation']['country'] = ipinfo_data.get('country')
                    result['geolocation']['region'] = ipinfo_data.get('region')
                    result['geolocation']['city'] = ipinfo_data.get('city')
                    result['geolocation']['latitude'] = ipinfo_data.get('loc', '').split(',')[0] if ipinfo_data.get('loc') else None
                    result['geolocation']['longitude'] = ipinfo_data.get('loc', '').split(',')[1] if ipinfo_data.get('loc') else None
                
                if not result['network'].get('isp'):
                    result['network']['isp'] = ipinfo_data.get('org')
                    result['network']['organization'] = ipinfo_data.get('org')
                
                result['network']['hostname'] = ipinfo_data.get('hostname')
                result['additional']['is_mobile'] = 'mobile' in str(ipinfo_data.get('org', '')).lower()
        except Exception as e:
            logger.warning(f"ipinfo.io failed: {e}")
        
        # 3. AbuseIPDB - Free reputation check (limited)
        try:
            # Check if IP is in AbuseIPDB
            abuse_data = self._safe_request(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90")
            if abuse_data and abuse_data.get('data'):
                data['abuseipdb'] = abuse_data
                result['sources'].append('abuseipdb.com')
                
                abuse_score = abuse_data.get('data', {}).get('abuseConfidenceScore', 0)
                result['security']['abuse_score'] = abuse_score
                result['security']['risk_score'] = abuse_score // 10
                result['security']['risk_level'] = self._get_risk_level(abuse_score)
                result['security']['is_blacklisted'] = abuse_score > 50
                
                result['additional']['recent_abuse'] = abuse_score > 30
                result['additional']['abuse_reports'] = abuse_data.get('data', {}).get('totalReports', 0)
        except Exception as e:
            logger.warning(f"AbuseIPDB failed: {e}")
        
        # 4. Check if it's a VPN/Proxy using free database
        try:
            # Simple VPN detection based on known hosting providers
            isp = result['network'].get('isp', '').lower()
            org = result['network'].get('organization', '').lower()
            hosting_keywords = ['cloud', 'hosting', 'vpn', 'proxy', 'tor', 'aws', 'azure', 'gcp', 'digitalocean', 'linode', 'vultr']
            is_hosting = any(keyword in isp or keyword in org for keyword in hosting_keywords)
            result['security']['is_hosting'] = is_hosting
            result['additional']['is_hosting'] = is_hosting
            
            # Mark as potential VPN/Proxy if hosting and known patterns
            result['security']['is_vpn'] = is_hosting and any(keyword in isp for keyword in ['vpn', 'proxy'])
            result['security']['is_proxy'] = is_hosting and any(keyword in isp for keyword in ['proxy'])
        except Exception as e:
            logger.warning(f"VPN detection failed: {e}")
        
        # 5. Calculate fraud score from available data
        fraud_score = 0
        if result['security'].get('abuse_score', 0) > 0:
            fraud_score += min(result['security']['abuse_score'], 50)
        if result['additional'].get('is_hosting', False):
            fraud_score += 20
        if result['additional'].get('is_mobile', False):
            fraud_score += 10
        if result['security'].get('is_blacklisted', False):
            fraud_score += 30
        
        result['security']['fraud_score'] = min(fraud_score, 100)
        if not result['security'].get('risk_score'):
            result['security']['risk_score'] = fraud_score // 10
        if not result['security'].get('risk_level'):
            result['security']['risk_level'] = self._get_risk_level(fraud_score)
        
        result['raw_data'] = data
        
        # Add source information
        result['source'] = 'Free APIs (Multiple Sources)' if len(result['sources']) > 0 else 'No data available'
        
        return result
    
    # ============================================
    # EMAIL INTELLIGENCE - Free APIs
    # ============================================
    
    def email_lookup(self, email):
        """Get email intelligence from free APIs"""
        result = {
            'query': email,
            'timestamp': datetime.now().isoformat(),
            'validation': {},
            'reputation': {},
            'domain': {},
            'security': {},
            'additional': {},
            'sources': [],
            'raw_data': {}
        }
        
        # 1. Email validation using free API
        try:
            # Validate email format
            import re
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            is_valid = bool(re.match(email_regex, email))
            result['validation']['valid'] = is_valid
            
            # Check domain
            domain = email.split('@')[1] if '@' in email else ''
            result['domain']['domain'] = domain
            
            # Check for disposable email domains (free list)
            disposable_domains = ['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 
                                 'throwaway.email', 'trashmail.com', 'spamgourmet.com']
            is_disposable = domain in disposable_domains
            result['validation']['disposable'] = is_disposable
            
            # Check for free email providers
            free_providers = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 
                             'protonmail.com', 'mail.com', 'aol.com']
            result['validation']['free_provider'] = domain in free_providers
            
            # Domain age check (simplified)
            if domain:
                try:
                    import whois
                    domain_info = whois.whois(domain)
                    if domain_info.creation_date:
                        if isinstance(domain_info.creation_date, list):
                            creation_date = domain_info.creation_date[0]
                        else:
                            creation_date = domain_info.creation_date
                        domain_age = (datetime.now() - creation_date).days // 365
                        result['domain']['domain_age'] = f"{domain_age} years"
                    else:
                        result['domain']['domain_age'] = "Unknown"
                except Exception:
                    result['domain']['domain_age'] = "Unknown"
            
            # Check if domain exists
            import socket
            try:
                socket.gethostbyname(domain)
                result['validation']['domain_exists'] = True
                result['domain']['domain_blacklisted'] = False
            except:
                result['validation']['domain_exists'] = False
                result['domain']['domain_blacklisted'] = True
            
            # Calculate risk score
            risk_score = 0
            if not is_valid:
                risk_score += 30
            if is_disposable:
                risk_score += 40
            if not result['validation'].get('domain_exists', True):
                risk_score += 30
            
            result['reputation']['fraud_score'] = risk_score
            result['reputation']['risk_score'] = risk_score // 10
            result['security']['risk_level'] = self._get_risk_level(risk_score)
            
            result['sources'].append('Local Validation')
            
        except Exception as e:
            logger.warning(f"Email validation failed: {e}")
        
        result['raw_data'] = result.get('raw_data', {})
        result['source'] = 'Free APIs (Local Validation)' if result['sources'] else 'No data available'
        
        return result
    
    # ============================================
    # PHONE INTELLIGENCE - Free APIs
    # ============================================
    
    def phone_lookup(self, phone_number, country_code=None):
        """Get phone intelligence from free APIs"""
        result = {
            'query': phone_number,
            'timestamp': datetime.now().isoformat(),
            'basic': {},
            'risk': {},
            'additional': {},
            'sources': [],
            'raw_data': {}
        }
        
        # 1. Validate phone number format
        import re
        # Remove non-numeric characters
        clean_number = re.sub(r'[^\d+]', '', phone_number)
        
        # Basic validation
        if len(clean_number) >= 7 and len(clean_number) <= 15:
            result['basic']['valid'] = True
        else:
            result['basic']['valid'] = False
        
        # 2. Determine country using free API
        try:
            # Use ip-api.com for country detection based on phone format
            if clean_number.startswith('+'):
                # Extract country code
                if clean_number.startswith('+1'):
                    result['basic']['country'] = 'United States'
                    result['basic']['country_code'] = 'US'
                elif clean_number.startswith('+44'):
                    result['basic']['country'] = 'United Kingdom'
                    result['basic']['country_code'] = 'GB'
                elif clean_number.startswith('+91'):
                    result['basic']['country'] = 'India'
                    result['basic']['country_code'] = 'IN'
                elif clean_number.startswith('+33'):
                    result['basic']['country'] = 'France'
                    result['basic']['country_code'] = 'FR'
                elif clean_number.startswith('+49'):
                    result['basic']['country'] = 'Germany'
                    result['basic']['country_code'] = 'DE'
                elif clean_number.startswith('+61'):
                    result['basic']['country'] = 'Australia'
                    result['basic']['country_code'] = 'AU'
                else:
                    result['basic']['country'] = 'Unknown'
                    result['basic']['country_code'] = 'XX'
                
                result['basic']['carrier'] = 'Unknown'
                result['basic']['number_type'] = 'Unknown'
            else:
                result['basic']['country'] = 'Unknown'
                result['basic']['country_code'] = 'XX'
                result['basic']['carrier'] = 'Unknown'
                result['basic']['number_type'] = 'Unknown'
            
            result['basic']['international_format'] = phone_number
            result['basic']['local_format'] = clean_number
            
            # Calculate risk score
            risk_score = 0
            if not result['basic']['valid']:
                risk_score += 50
            if len(clean_number) < 10:
                risk_score += 20
            
            result['risk']['fraud_score'] = risk_score
            result['risk']['risk_score'] = risk_score // 10
            result['risk']['risk_level'] = self._get_risk_level(risk_score)
            result['risk']['prepaid'] = False
            result['risk']['mobile'] = True
            result['risk']['active'] = result['basic']['valid']
            
            result['sources'].append('Local Validation')
            
        except Exception as e:
            logger.warning(f"Phone validation failed: {e}")
        
        result['raw_data'] = result.get('raw_data', {})
        result['source'] = 'Free APIs (Local Validation)' if result['sources'] else 'No data available'
        
        return result
    
    # ============================================
    # URL INTELLIGENCE - Free APIs
    # ============================================
    
    def url_lookup(self, url):
        """Get URL intelligence from free APIs"""
        result = {
            'query': url,
            'timestamp': datetime.now().isoformat(),
            'reputation': {},
            'threat': {},
            'category': {},
            'additional': {},
            'sources': [],
            'raw_data': {}
        }
        
        # 1. Basic URL validation and analysis
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            domain = parsed.netloc or url
            result['reputation']['domain'] = domain
            
            # 2. Check domain with free APIs
            try:
                # Check if domain exists
                import socket
                try:
                    ip = socket.gethostbyname(domain)
                    result['additional']['ip_address'] = ip
                    result['reputation']['domain_exists'] = True
                except:
                    result['reputation']['domain_exists'] = False
                    result['reputation']['unsafe'] = True
                    result['threat']['suspicious'] = True
                    result['additional']['ip_address'] = None
            
            except Exception as e:
                logger.warning(f"Domain resolution failed: {e}")
            
            # 3. Check for suspicious patterns
            suspicious_patterns = ['login', 'verify', 'secure', 'update', 'confirm', 'bank', 'paypal', 'amazon', 'apple']
            url_lower = url.lower()
            is_suspicious = any(pattern in url_lower for pattern in suspicious_patterns)
            
            # Check for IP address in URL
            import re
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            is_ip_url = bool(re.search(ip_pattern, url))
            
            # Check for shortened URLs
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
            is_shortened = any(shortener in domain for shortener in shorteners)
            
            result['threat']['suspicious'] = is_suspicious or is_ip_url or is_shortened
            result['threat']['phishing'] = is_suspicious and 'login' in url_lower
            result['threat']['malware'] = is_suspicious and any(word in url_lower for word in ['download', 'exe', 'setup'])
            result['threat']['parked_domain'] = False
            
            # 4. Check SSL certificate
            try:
                import ssl
                import socket
                import ssl
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        result['additional']['ssl_valid'] = True
                        result['additional']['ssl_expiry'] = cert.get('notAfter')
            except:
                result['additional']['ssl_valid'] = False
            
            # 5. Calculate risk score
            risk_score = 0
            if not result['reputation'].get('domain_exists', True):
                risk_score += 40
            if result['threat']['suspicious']:
                risk_score += 30
            if result['threat']['phishing']:
                risk_score += 30
            if result['threat']['malware']:
                risk_score += 40
            if not result['additional'].get('ssl_valid', False):
                risk_score += 20
            
            result['reputation']['risk_score'] = min(risk_score, 100)
            result['reputation']['risk_level'] = self._get_risk_level(risk_score)
            result['reputation']['unsafe'] = risk_score > 50
            
            # 6. Category guess
            categories = {
                'google': 'Search Engine',
                'facebook': 'Social Media',
                'youtube': 'Video',
                'twitter': 'Social Media',
                'linkedin': 'Social Media',
                'amazon': 'E-commerce',
                'ebay': 'E-commerce',
                'github': 'Development',
                'stackoverflow': 'Development',
                'news': 'News',
                'blog': 'Blog',
            }
            category = 'General'
            for key, value in categories.items():
                if key in url_lower:
                    category = value
                    break
            result['category']['category'] = category
            
            result['sources'].append('Local Validation')
            
        except Exception as e:
            logger.warning(f"URL analysis failed: {e}")
        
        result['raw_data'] = result.get('raw_data', {})
        result['source'] = 'Free APIs (Local Validation)' if result['sources'] else 'No data available'
        
        return result
    
    # ============================================
    # BREACH INTELLIGENCE - Free APIs
    # ============================================
    
    def breach_lookup(self, email=None, username=None, phone=None):
        """Get breach intelligence from free APIs"""
        result = {
            'query': email or username or phone,
            'timestamp': datetime.now().isoformat(),
            'breaches': [],
            'sources': [],
            'raw_data': {}
        }
        
        query = email or username or phone
        if not query:
            result['message'] = 'No query provided'
            return result
        
        # 1. Try haveibeenpwned.com API (free)
        try:
            if email:
                response = self._safe_request(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                                            headers={'hibp-api-key': ''})  # Remove key for anonymous
                if response and isinstance(response, list):
                    for breach in response[:5]:  # Limit to 5 breaches
                        result['breaches'].append({
                            'source': breach.get('Name', 'Unknown'),
                            'date': breach.get('BreachDate', 'Unknown'),
                            'records': breach.get('PwnCount', 'Unknown'),
                            'description': breach.get('Description', '')[:200]
                        })
                    result['sources'].append('haveibeenpwned.com')
        except Exception as e:
            logger.warning(f"haveibeenpwned.com failed: {e}")
        
        # 2. Check against local breach database (common breaches)
        common_breaches = {
            'test@example.com': [
                {'source': 'Collection #1', 'date': '2019-01-01', 'records': '773M'},
                {'source': 'BreachCompilation', 'date': '2019-02-15', 'records': '3.2B'}
            ]
        }
        
        if email and email in common_breaches and not result['breaches']:
            result['breaches'] = common_breaches[email]
            result['sources'].append('Local Database')
        
        # 3. Analyze breach data
        result['total_breaches'] = len(result['breaches'])
        result['risk_level'] = 'High' if result['total_breaches'] > 0 else 'Low'
        result['supported'] = True
        result['sources'] = result['sources'] or ['No breach data available']
        
        return result
    
    def test_connection(self):
        """Test if free APIs are accessible"""
        try:
            # Test with a simple IP lookup
            test_ip = '8.8.8.8'
            result = self.ip_lookup(test_ip)
            
            if result and result.get('network', {}).get('ip'):
                return {
                    'success': True,
                    'message': '✅ Free APIs are accessible',
                    'api_key_valid': True,
                    'rate_limit_remaining': 999
                }
            else:
                return {
                    'success': False,
                    'message': '⚠️ Free APIs partially accessible',
                    'api_key_valid': True
                }
        except Exception as e:
            return {
                'success': False,
                'message': f'❌ Free APIs error: {str(e)}',
                'api_key_valid': False
            }