from django.urls import path
from . import views

app_name = 'intelligence'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),
    
    # Lookups
    path('ip/', views.ip_lookup, name='ip_lookup'),
    path('email/', views.email_lookup, name='email_lookup'),
    path('phone/', views.phone_lookup, name='phone_lookup'),
    path('url/', views.url_lookup, name='url_lookup'),
    path('breach/', views.breach_lookup, name='breach_lookup'),
    
    # History
    path('history/', views.search_history, name='search_history'),
    path('history/<int:search_id>/', views.search_detail, name='search_detail'),
    
    # Reports
    path('report/<int:search_id>/', views.generate_report, name='generate_report'),
    path('report/download/<int:report_id>/', views.download_report, name='download_report'),
    
    # Settings
    path('settings/', views.settings, name='settings'),
    path('settings/test/', views.test_api, name='test_api'),
    path('settings/audit/', views.audit_log, name='audit_log'),
]