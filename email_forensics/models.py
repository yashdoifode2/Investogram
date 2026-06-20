from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid

User = get_user_model()

class EmailAnalysis(models.Model):
    """Main model for email forensic analysis"""
    
    RISK_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_analyses')
    
    # Original email data
    filename = models.CharField(max_length=255, blank=True)
    raw_email = models.TextField()
    parsed_email = models.JSONField(default=dict)
    
    # Analysis results
    headers = models.JSONField(default=dict)
    spf_result = models.JSONField(default=dict)
    dkim_result = models.JSONField(default=dict)
    dmarc_result = models.JSONField(default=dict)
    route_timeline = models.JSONField(default=list)
    
    # Intelligence data
    domain_intelligence = models.JSONField(default=dict)
    ip_intelligence = models.JSONField(default=list)
    url_findings = models.JSONField(default=list)
    attachment_findings = models.JSONField(default=list)
    iocs = models.JSONField(default=dict)
    
    # OSINT data
    osint_data = models.JSONField(default=dict)
    social_profiles = models.JSONField(default=list)
    github_findings = models.JSONField(default=list)
    breach_data = models.JSONField(default=list)
    gravatar_data = models.JSONField(default=dict)
    
    # Scoring
    threat_score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS, default='LOW')
    
    # Status
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    error_message = models.TextField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    analysis_duration = models.FloatField(default=0)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['risk_level']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"Analysis {self.id} - {self.created_at}"
    
    def get_risk_color(self):
        colors = {
            'LOW': '#00d4aa',
            'MEDIUM': '#ffa502',
            'HIGH': '#ff4757',
            'CRITICAL': '#ff0000'
        }
        return colors.get(self.risk_level, '#888')


class IOC(models.Model):
    """Indicators of Compromise extracted from emails"""
    
    IOC_TYPES = [
        ('EMAIL', 'Email Address'),
        ('DOMAIN', 'Domain'),
        ('URL', 'URL'),
        ('IPV4', 'IPv4 Address'),
        ('IPV6', 'IPv6 Address'),
        ('MD5', 'MD5 Hash'),
        ('SHA1', 'SHA1 Hash'),
        ('SHA256', 'SHA256 Hash'),
    ]
    
    analysis = models.ForeignKey(EmailAnalysis, on_delete=models.CASCADE, related_name='ioc_objects')
    ioc_type = models.CharField(max_length=10, choices=IOC_TYPES)
    value = models.CharField(max_length=500)
    context = models.TextField(blank=True)
    is_malicious = models.BooleanField(default=False)
    threat_score = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['ioc_type', 'value']),
            models.Index(fields=['is_malicious']),
        ]
    
    def __str__(self):
        return f"{self.get_ioc_type_display()}: {self.value}"


class EmailReport(models.Model):
    """Generated reports for email analyses"""
    
    analysis = models.ForeignKey(EmailAnalysis, on_delete=models.CASCADE, related_name='reports')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_reports')
    
    file_path = models.CharField(max_length=500)
    file_size = models.IntegerField(default=0)
    format = models.CharField(max_length=10, default='PDF')
    
    generated_at = models.DateTimeField(auto_now_add=True)
    download_count = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-generated_at']
    
    def __str__(self):
        return f"Report for {self.analysis.id} - {self.generated_at}"


class AnalysisHistory(models.Model):
    """Audit log for email analysis actions"""
    
    ACTION_TYPES = [
        ('UPLOAD', 'Email Uploaded'),
        ('ANALYZE', 'Analysis Started'),
        ('COMPLETE', 'Analysis Completed'),
        ('FAILED', 'Analysis Failed'),
        ('REPORT', 'Report Generated'),
        ('DOWNLOAD', 'Report Downloaded'),
    ]
    
    analysis = models.ForeignKey(EmailAnalysis, on_delete=models.CASCADE, related_name='history')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_history')
    action = models.CharField(max_length=10, choices=ACTION_TYPES)
    details = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.get_action_display()} - {self.timestamp}"