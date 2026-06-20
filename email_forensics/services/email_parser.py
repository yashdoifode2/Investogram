"""
Email Parser Service - Parses email files and extracts metadata
"""

import email
import re
from email import policy
from email.parser import BytesParser, Parser
from datetime import datetime
import logging
import base64
from email.header import decode_header
import quopri

logger = logging.getLogger(__name__)

class EmailParser:
    """Parse email files and extract structured data"""
    
    def __init__(self):
        self.raw_content = None
        self.parsed = {}
    
    def parse_bytes(self, content):
        """Parse email from bytes content"""
        try:
            msg = BytesParser(policy=policy.default).parsebytes(content)
            self.raw_content = content
            return self._parse_message(msg)
        except Exception as e:
            logger.error(f"Error parsing email: {e}")
            raise ValueError(f"Invalid email format: {str(e)}")
    
    def parse_text(self, content):
        """Parse email from text content"""
        try:
            msg = Parser(policy=policy.default).parsestr(content)
            self.raw_content = content.encode()
            return self._parse_message(msg)
        except Exception as e:
            logger.error(f"Error parsing email: {e}")
            raise ValueError(f"Invalid email format: {str(e)}")
    
    def _parse_message(self, msg):
        """Parse email message object"""
        result = {
            'headers': {},
            'body': '',
            'html_body': '',
            'attachments': [],
            'urls': [],
            'raw': self.raw_content,
        }
        
        # Parse headers
        for key, value in msg.items():
            decoded = self._decode_header(value)
            result['headers'][key.lower()] = decoded
        
        # Extract body
        body = ""
        html_body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    body = self._get_body(part)
                elif content_type == 'text/html':
                    html_body = self._get_body(part)
                elif part.get_content_maintype() == 'multipart':
                    continue
                else:
                    if part.get_filename():
                        attachment = self._parse_attachment(part)
                        result['attachments'].append(attachment)
        else:
            body = self._get_body(msg)
        
        result['body'] = body
        result['html_body'] = html_body
        
        # Extract URLs from body
        result['urls'] = self._extract_urls(body + html_body)
        
        # Extract key headers
        result['from'] = result['headers'].get('from', '')
        result['to'] = result['headers'].get('to', '')
        result['subject'] = result['headers'].get('subject', '')
        result['date'] = result['headers'].get('date', '')
        result['message_id'] = result['headers'].get('message-id', '')
        result['reply_to'] = result['headers'].get('reply-to', '')
        result['return_path'] = result['headers'].get('return-path', '')
        result['received'] = result['headers'].get('received', [])
        result['authentication_results'] = result['headers'].get('authentication-results', '')
        result['dkim_signature'] = result['headers'].get('dkim-signature', '')
        
        return result
    
    def _decode_header(self, value):
        """Decode email header value"""
        if isinstance(value, str):
            return value
        
        decoded_parts = []
        for part, encoding in decode_header(value):
            if isinstance(part, bytes):
                try:
                    if encoding:
                        part = part.decode(encoding)
                    else:
                        part = part.decode('utf-8', errors='ignore')
                except:
                    part = part.decode('utf-8', errors='ignore')
            decoded_parts.append(str(part))
        
        return ''.join(decoded_parts)
    
    def _get_body(self, part):
        """Extract body from email part"""
        payload = part.get_payload(decode=True)
        
        if not payload:
            return ""
        
        charset = part.get_content_charset() or 'utf-8'
        try:
            return payload.decode(charset, errors='ignore')
        except:
            try:
                return payload.decode('utf-8', errors='ignore')
            except:
                return str(payload)
    
    def _parse_attachment(self, part):
        """Parse email attachment"""
        filename = part.get_filename()
        if filename:
            filename = self._decode_header(filename)
        else:
            filename = 'unnamed'
        
        payload = part.get_payload(decode=True)
        
        return {
            'filename': filename,
            'content_type': part.get_content_type(),
            'size': len(payload) if payload else 0,
            'content': base64.b64encode(payload).decode('utf-8') if payload else None,
            'hash': self._compute_hash(payload) if payload else None,
        }
    
    def _compute_hash(self, content):
        """Compute hash of attachment content"""
        import hashlib
        return {
            'md5': hashlib.md5(content).hexdigest(),
            'sha1': hashlib.sha1(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest(),
        }
    
    def _extract_urls(self, text):
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s<>"\'(){}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))