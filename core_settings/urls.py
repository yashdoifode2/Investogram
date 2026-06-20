from django.urls import path
from . import views

app_name = 'core_settings'

urlpatterns = [
    path('api-services/', views.api_services, name='api_services'),
    path('api-services/create/', views.api_service_create, name='api_service_create'),
    path('api-services/<int:service_id>/edit/', views.api_service_edit, name='api_service_edit'),
    path('api-services/<int:service_id>/delete/', views.api_service_delete, name='api_service_delete'),
    path('api-services/<int:service_id>/test/', views.api_service_test, name='api_service_test'),
    path('api-services/<int:service_id>/toggle/', views.api_service_toggle, name='api_service_toggle'),
    path('api-usage/', views.api_usage_logs, name='api_usage_logs'),
    path('api-usage/clear/', views.api_usage_clear, name='api_usage_clear'),
    path('audit-log/', views.audit_log, name='audit_log'),
    # API Status endpoint
    path('api-status/', views.api_status_json, name='api_status_json'),
]