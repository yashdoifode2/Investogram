from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()

class IntelligenceSearch(models.Model):
    SEARCH_TYPES = [
        ('IP', 'IP Address'),
        ('EMAIL', 'Email Address'),
        ('PHONE', 'Phone Number'),
        ('URL', 'URL/Domain'),
        ('BREACH', 'Breach Intelligence'),
    ]
    
    search_type = models.CharField(max_length=10, choices=SEARCH_TYPES)
    query = models.CharField(max_length=500)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='intelligence_searches')
    results = models.JSONField(default=dict)
    risk_score = models.IntegerField(null=True, blank=True)
    risk_level = models.CharField(max_length=20, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_high_risk = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['search_type', 'timestamp']),
            models.Index(fields=['risk_score']),
        ]
    
    def __str__(self):
        return f"{self.get_search_type_display()}: {self.query} - {self.timestamp}"

class IntelligenceReport(models.Model):
    REPORT_FORMATS = [
        ('PDF', 'PDF'),
        ('CSV', 'CSV'),
        ('JSON', 'JSON'),
    ]
    
    search = models.ForeignKey(IntelligenceSearch, on_delete=models.CASCADE, related_name='reports')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='intelligence_reports')
    report_format = models.CharField(max_length=4, choices=REPORT_FORMATS)
    file_path = models.CharField(max_length=500)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)
    download_count = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-generated_at']
    
    def __str__(self):
        return f"{self.title} - {self.generated_at}"

class APIConfiguration(models.Model):
    api_key = models.CharField(max_length=255)
    is_enabled = models.BooleanField(default=True)
    last_test = models.DateTimeField(null=True, blank=True)
    test_status = models.BooleanField(default=False)
    test_message = models.TextField(blank=True)
    rate_limit_remaining = models.IntegerField(default=1000)
    rate_limit_reset = models.DateTimeField(null=True, blank=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='intelligence_api_config_updates')
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'API Configuration'
        verbose_name_plural = 'API Configurations'
    
    def __str__(self):
        return f"IPQS Configuration - {'Enabled' if self.is_enabled else 'Disabled'}"

class APIAuditLog(models.Model):
    ACTION_TYPES = [
        ('CONFIG_UPDATE', 'Configuration Updated'),
        ('CONFIG_TEST', 'Configuration Tested'),
        ('API_CALL', 'API Call'),
        ('API_ERROR', 'API Error'),
        ('KEY_CHANGE', 'API Key Changed'),
        ('ENABLE', 'API Enabled'),
        ('DISABLE', 'API Disabled'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='intelligence_audit_logs')
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
    
    def __str__(self):
        return f"{self.get_action_display()} - {self.timestamp}"