from django.contrib import admin
from .models import IntelligenceSearch, IntelligenceReport, APIConfiguration, APIAuditLog

@admin.register(IntelligenceSearch)
class IntelligenceSearchAdmin(admin.ModelAdmin):
    list_display = ['search_type', 'query', 'user', 'risk_level', 'timestamp']
    list_filter = ['search_type', 'risk_level', 'is_high_risk', 'timestamp']
    search_fields = ['query', 'user__username', 'user__email']
    readonly_fields = ['results']
    date_hierarchy = 'timestamp'

@admin.register(IntelligenceReport)
class IntelligenceReportAdmin(admin.ModelAdmin):
    list_display = ['title', 'user', 'report_format', 'generated_at', 'download_count']
    list_filter = ['report_format', 'generated_at']
    search_fields = ['title', 'user__username']

@admin.register(APIConfiguration)
class APIConfigurationAdmin(admin.ModelAdmin):
    list_display = ['is_enabled', 'last_test', 'test_status', 'updated_at']
    readonly_fields = ['last_test', 'test_status', 'test_message', 'updated_at']

@admin.register(APIAuditLog)
class APIAuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'timestamp']
    list_filter = ['action', 'timestamp']
    search_fields = ['user__username', 'details']
    readonly_fields = ['details']