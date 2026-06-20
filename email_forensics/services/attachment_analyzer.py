"""
Attachment Analyzer - Analyzes attachments for threats
"""

import os
import logging
import hashlib
import base64
import mimetypes
from zipfile import ZipFile
import io

logger = logging.getLogger(__name__)

class AttachmentAnalyzer:
    """Analyze email attachments for threats"""
    
    def __init__(self, attachment_data):
        self.attachment = attachment_data
        self.filename = attachment_data.get('filename', '')
        self.content = attachment_data.get('content')
        self.content_type = attachment_data.get('content_type', '')
        self.size = attachment_data.get('size', 0)
        self.hash = attachment_data.get('hash', {})
        self.findings = {}
        self._analyze()
    
    def _analyze(self):
        """Perform comprehensive attachment analysis"""
        self.findings = {
            'filename': self.filename,
            'content_type': self.content_type,
            'size': self.size,
            'hash': self.hash,
            'is_suspicious': False,
            'is_malicious': False,
            'risks': [],
            'detected_macros': False,
            'detected_executables': False,
            'file_extension': os.path.splitext(self.filename)[1].lower() if self.filename else '',
            'mime_type': self._detect_mime_type(),
        }
        
        # Check for suspicious extensions
        self._check_extension()
        
        # Check for executables
        self._check_executable()
        
        # Check for macros (in Office documents)
        self._check_macros()
        
        # Check for dangerous content in text files
        self._check_dangerous_content()
    
    def _detect_mime_type(self):
        """Detect MIME type"""
        if self.content_type:
            return self.content_type
        if self.filename:
            mime_type, _ = mimetypes.guess_type(self.filename)
            return mime_type or 'application/octet-stream'
        return 'application/octet-stream'
    
    def _check_extension(self):
        """Check for suspicious file extensions"""
        suspicious_extensions = [
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.hta',
            '.vbs', '.js', '.jse', '.jar', '.app', '.msi', '.msp',
            '.docm', '.xlsm', '.pptm', '.dotm', '.xlam', '.ppam'
        ]
        
        if self.findings['file_extension'] in suspicious_extensions:
            self.findings['is_suspicious'] = True
            self.findings['risks'].append(f'Suspicious extension: {self.findings["file_extension"]}')
        
        # High-risk extensions
        high_risk_extensions = ['.exe', '.bat', '.cmd', '.vbs', '.js']
        if self.findings['file_extension'] in high_risk_extensions:
            self.findings['is_malicious'] = True
            self.findings['risks'].append(f'High-risk extension: {self.findings["file_extension"]}')
    
    def _check_executable(self):
        """Check if file is executable"""
        if self.findings['file_extension'] in ['.exe', '.bat', '.cmd', '.com', '.pif', '.scr']:
            self.findings['detected_executables'] = True
            self.findings['is_malicious'] = True
            self.findings['risks'].append('Executable file detected')
    
    def _check_macros(self):
        """Check for macros in Office documents"""
        if self.findings['file_extension'] in ['.docm', '.xlsm', '.pptm', '.dotm']:
            self.findings['detected_macros'] = True
            self.findings['is_suspicious'] = True
            self.findings['risks'].append('Macro-enabled document detected')
        
        # Check content for macro indicators in text files
        if self.content and self.findings['file_extension'] in ['.doc', '.xls', '.ppt']:
            try:
                content_str = base64.b64decode(self.content).decode('utf-8', errors='ignore')
                if 'Sub ' in content_str or 'Function ' in content_str or 'Dim ' in content_str:
                    self.findings['detected_macros'] = True
                    self.findings['is_suspicious'] = True
                    self.findings['risks'].append('Potential macro code detected in document')
            except:
                pass
    
    def _check_dangerous_content(self):
        """Check for dangerous content in text files"""
        if not self.content:
            return
        
        try:
            content_str = base64.b64decode(self.content).decode('utf-8', errors='ignore')
            
            # Check for JavaScript code
            if 'javascript:' in content_str.lower() or 'onclick=' in content_str.lower():
                self.findings['is_suspicious'] = True
                self.findings['risks'].append('JavaScript code detected')
            
            # Check for HTML with scripts
            if '<script>' in content_str.lower() and '</script>' in content_str.lower():
                self.findings['is_suspicious'] = True
                self.findings['risks'].append('HTML with embedded script detected')
            
            # Check for VBA code
            if 'vba' in content_str.lower() or 'vbscript' in content_str.lower():
                self.findings['is_suspicious'] = True
                self.findings['risks'].append('VBA/VBScript detected')
            
        except Exception as e:
            logger.warning(f"Content analysis failed: {e}")
    
    def get_findings(self):
        """Get all findings"""
        return self.findings
    
    def get_risk_level(self):
        """Get overall risk level"""
        if self.findings['is_malicious']:
            return 'CRITICAL'
        elif self.findings['is_suspicious']:
            return 'HIGH'
        elif self.findings['detected_executables']:
            return 'HIGH'
        elif self.findings['detected_macros']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_summary(self):
        """Get summary of findings"""
        return {
            'filename': self.filename,
            'size': self.size,
            'risk_level': self.get_risk_level(),
            'is_suspicious': self.findings['is_suspicious'],
            'is_malicious': self.findings['is_malicious'],
            'risks': self.findings['risks'],
            'hash': self.hash
        }