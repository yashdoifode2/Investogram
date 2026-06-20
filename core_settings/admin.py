from django.contrib import admin
from .models import APIService, APIUsageLog, APIAuditLog

@admin.register(APIService)
class APIServiceAdmin(admin.ModelAdmin):
    list_display = ['name', 'service_type', 'is_enabled', 'is_verified', 'created_at']
    list_filter = ['service_type', 'is_enabled', 'is_verified']
    search_fields = ['name', 'service_type']
    readonly_fields = ['created_at', 'updated_at']
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'service_type', 'is_enabled')
        }),
        ('API Configuration', {
            'fields': ('api_key', 'base_url', 'timeout', 'max_retries')
        }),
        ('Rate Limiting', {
            'fields': ('rate_limit', 'rate_limit_period')
        }),
        ('Status', {
            'fields': ('is_verified', 'last_verified')
        }),
        ('Metadata', {
            'fields': ('created_by', 'updated_by', 'created_at', 'updated_at')
        }),
    )
    
    def save_model(self, request, obj, form, change):
        if not obj.pk:
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)

@admin.register(APIUsageLog)
class APIUsageLogAdmin(admin.ModelAdmin):
    list_display = ['service', 'user', 'endpoint', 'response_status', 'response_time', 'is_error', 'timestamp']
    list_filter = ['service', 'is_error', 'response_status', 'timestamp']
    search_fields = ['endpoint', 'user__username', 'service__name']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'

@admin.register(APIAuditLog)
class APIAuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'timestamp']
    list_filter = ['action', 'timestamp']
    search_fields = ['user__username', 'details']
    readonly_fields = ['details', 'timestamp']