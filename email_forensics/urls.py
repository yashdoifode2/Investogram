from django.urls import path
from . import views

app_name = 'email_forensics'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),
    
    # Analysis
    path('analyze/', views.analyze_email, name='analyze_email'),
    path('result/<uuid:analysis_id>/', views.analysis_result, name='analysis_result'),
    path('history/', views.analysis_history, name='analysis_history'),
    path('delete/<uuid:analysis_id>/', views.delete_analysis, name='delete_analysis'),
    
    # Reports
    path('report/<uuid:analysis_id>/', views.generate_report, name='generate_report'),
    path('report/download/<int:report_id>/', views.download_report, name='download_report'),
    
    # IOCs
    path('iocs/<uuid:analysis_id>/', views.view_iocs, name='view_iocs'),
    path('iocs/export/<uuid:analysis_id>/', views.export_iocs, name='export_iocs'),
    
    # New Intelligence Views
    path('breach-intelligence/', views.breach_intelligence, name='breach_intelligence'),
    path('social-discovery/', views.social_discovery, name='social_discovery'),
    path('attachment-analysis/<uuid:analysis_id>/', views.attachment_analysis, name='attachment_analysis'),
    
    # API
    path('api/analyze/', views.api_analyze_email, name='api_analyze_email'),
]