from django.contrib import admin
from .models import EmailAnalysis, IOC, EmailReport, AnalysisHistory

@admin.register(EmailAnalysis)
class EmailAnalysisAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'risk_level', 'status', 'created_at']
    list_filter = ['risk_level', 'status', 'created_at']
    search_fields = ['user__username', 'filename']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'

@admin.register(IOC)
class IOCAdmin(admin.ModelAdmin):
    list_display = ['ioc_type', 'value', 'is_malicious', 'created_at']
    list_filter = ['ioc_type', 'is_malicious']
    search_fields = ['value']

@admin.register(EmailReport)
class EmailReportAdmin(admin.ModelAdmin):
    list_display = ['analysis', 'user', 'format', 'generated_at', 'download_count']
    list_filter = ['format', 'generated_at']

@admin.register(AnalysisHistory)
class AnalysisHistoryAdmin(admin.ModelAdmin):
    list_display = ['analysis', 'user', 'action', 'timestamp']
    list_filter = ['action', 'timestamp']