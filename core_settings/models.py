from django.db import models
from django.contrib.auth import get_user_model
from django.conf import settings
from cryptography.fernet import Fernet

User = get_user_model()

class APIService(models.Model):
    """Model for storing API service configurations per user"""
    
    SERVICE_TYPES = [
        ('IPQS', 'IPQualityScore'),
        ('VT', 'VirusTotal'),
        ('SHODAN', 'Shodan'),
        ('ABUSEIPDB', 'AbuseIPDB'),
        ('GREYNOISE', 'GreyNoise'),
        ('CUSTOM', 'Custom API'),
    ]
    
    RATE_LIMIT_PERIODS = [
        ('minute', 'Per Minute'),
        ('hour', 'Per Hour'),
        ('day', 'Per Day'),
        ('month', 'Per Month'),
    ]
    
    name = models.CharField(max_length=100)
    service_type = models.CharField(max_length=20, choices=SERVICE_TYPES)
    api_key = models.CharField(max_length=500)
    base_url = models.URLField(blank=True, help_text="Optional: Override default API endpoint")
    is_enabled = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    last_verified = models.DateTimeField(null=True, blank=True)
    rate_limit = models.IntegerField(default=1000, help_text="Maximum requests per period")
    rate_limit_period = models.CharField(max_length=20, choices=RATE_LIMIT_PERIODS, default='day')
    timeout = models.IntegerField(default=30, help_text="Request timeout in seconds")
    max_retries = models.IntegerField(default=3, help_text="Maximum retry attempts on failure")
    extra_config = models.JSONField(default=dict, blank=True)
    
    # User ownership
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_services')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['service_type']
        verbose_name = 'API Service'
        verbose_name_plural = 'API Services'
        unique_together = ['user', 'service_type']
    
    def __str__(self):
        return f"{self.user.username} - {self.get_service_type_display()}"
    
    def get_decrypted_key(self):
        """Get decrypted API key"""
        if settings.FERNET:
            try:
                return settings.FERNET.decrypt(self.api_key.encode()).decode()
            except Exception:
                return self.api_key
        return self.api_key
    
    def set_encrypted_key(self, key):
        """Set encrypted API key"""
        if settings.FERNET:
            try:
                self.api_key = settings.FERNET.encrypt(key.encode()).decode()
            except Exception:
                self.api_key = key
        else:
            self.api_key = key
    
    def save(self, *args, **kwargs):
        if self.api_key and not self.api_key.startswith('gAAAAAB'):
            self.set_encrypted_key(self.api_key)
        super().save(*args, **kwargs)


class APIUsageLog(models.Model):
    """Model for tracking API usage per user"""
    
    service = models.ForeignKey(APIService, on_delete=models.CASCADE, related_name='usage_logs')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_usage_logs')
    endpoint = models.CharField(max_length=255)
    method = models.CharField(max_length=10)
    request_data = models.JSONField(default=dict, blank=True)
    response_status = models.IntegerField()
    response_data = models.JSONField(default=dict, blank=True)
    response_time = models.FloatField(help_text="Response time in seconds")
    is_error = models.BooleanField(default=False)
    error_message = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['service', 'timestamp']),
            models.Index(fields=['is_error']),
        ]
        verbose_name = 'API Usage Log'
        verbose_name_plural = 'API Usage Logs'
    
    def __str__(self):
        return f"{self.user.username} - {self.service.name} - {self.timestamp}"


class APIAuditLog(models.Model):
    """Model for API audit logging per user"""
    
    ACTION_TYPES = [
        ('CONFIG_UPDATE', 'Configuration Updated'),
        ('CONFIG_TEST', 'Configuration Tested'),
        ('API_CALL', 'API Call'),
        ('API_ERROR', 'API Error'),
        ('KEY_CHANGE', 'API Key Changed'),
        ('ENABLE', 'API Enabled'),
        ('DISABLE', 'API Disabled'),
        ('SERVICE_CREATE', 'Service Created'),
        ('SERVICE_UPDATE', 'Service Updated'),
        ('SERVICE_DELETE', 'Service Deleted'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='audit_logs')
    action = models.CharField(max_length=20, choices=ACTION_TYPES)
    details = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action']),
        ]
        verbose_name = 'API Audit Log'
        verbose_name_plural = 'API Audit Logs'
    
    def __str__(self):
        return f"{self.user.username} - {self.get_action_display()} - {self.timestamp}"