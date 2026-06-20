from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponse
from django.db.models import Count, Q
from django.utils import timezone
from django.conf import settings  # Proper import
import json
import os
from datetime import datetime, timedelta

from .models import IntelligenceSearch, IntelligenceReport, APIConfiguration, APIAuditLog
from .forms import (
    IPLookupForm, EmailLookupForm, PhoneLookupForm, 
    URLLookupForm, BreachLookupForm, APISettingsForm
)
from .decorators import admin_required
from .services.intelligence_service import IntelligenceService
from .services.report_generator import ReportGenerator


# ============================================
# DASHBOARD VIEW
# ============================================

@login_required
def dashboard(request):
    """Intelligence dashboard"""
    user = request.user
    
    # Statistics
    total_searches = IntelligenceSearch.objects.filter(user=user).count()
    high_risk_count = IntelligenceSearch.objects.filter(user=user, is_high_risk=True).count()
    recent_searches = IntelligenceSearch.objects.filter(user=user)[:10]
    
    # Risk distribution
    risk_distribution = IntelligenceSearch.objects.filter(user=user).values('risk_level').annotate(
        count=Count('id')
    )
    
    # Most queried indicators
    most_queried = IntelligenceSearch.objects.filter(user=user).values('query').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Get API status from core_settings
    try:
        from core_settings.views import check_api_status
        api_status = check_api_status(user)
    except ImportError:
        api_status = {
            'has_key': False,
            'is_verified': False,
            'status': 'API status check unavailable',
            'status_class': 'inactive'
        }
    
    context = {
        'total_searches': total_searches,
        'high_risk_count': high_risk_count,
        'recent_searches': recent_searches,
        'risk_distribution': risk_distribution,
        'most_queried': most_queried,
        'api_status': api_status,
        'active_tab': 'dashboard',
    }
    return render(request, 'intelligence/dashboard.html', context)


# ============================================
# INTELLIGENCE LOOKUP VIEWS
# ============================================

@login_required
def ip_lookup(request):
    """IP intelligence lookup with fallback to free APIs"""
    form = IPLookupForm(request.POST or None)
    result = None
    service_used = None
    
    if request.method == 'POST' and form.is_valid():
        ip = form.cleaned_data['ip_address']
        strictness = form.cleaned_data.get('strictness', 1)
        fast = form.cleaned_data.get('fast', False)
        
        try:
            service = IntelligenceService(user=request.user)
            data = service.ip_lookup(ip, strictness=strictness, fast=fast)
            service_used = data.get('source', 'Unknown')
            
            if data.get('error'):
                messages.warning(request, f"IP lookup returned with errors: {data.get('message', 'Unknown error')}")
            
            search = IntelligenceSearch.objects.create(
                search_type='IP',
                query=ip,
                user=request.user,
                results=data,
                risk_score=data.get('security', {}).get('risk_score') if not data.get('error') else None,
                risk_level=data.get('security', {}).get('risk_level') if not data.get('error') else 'Unknown',
                is_high_risk=data.get('security', {}).get('risk_score', 0) >= 6 if not data.get('error') else False,
                ip_address=ip
            )
            
            result = {
                'id': search.id,
                'search_type': 'IP',
                'query': ip,
                'risk_level': search.risk_level,
                'results': data,
                'timestamp': search.timestamp,
                'source': service_used,
                'is_fallback': data.get('is_fallback', False)
            }
            
            if data.get('is_fallback'):
                messages.info(request, f"Using free APIs for IP lookup (IPQS unavailable or failed)")
            else:
                messages.success(request, f"IP lookup completed for {ip}")
            
        except Exception as e:
            messages.error(request, f"IP lookup failed: {str(e)}")
    
    context = {
        'form': form,
        'result': result,
        'service_used': service_used,
        'active_tab': 'ip',
    }
    return render(request, 'intelligence/ip_lookup.html', context)


@login_required
def email_lookup(request):
    """Email intelligence lookup with fallback to free APIs"""
    form = EmailLookupForm(request.POST or None)
    result = None
    service_used = None
    
    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        
        try:
            service = IntelligenceService(user=request.user)
            data = service.email_lookup(email)
            service_used = data.get('source', 'Unknown')
            
            if data.get('error'):
                messages.warning(request, f"Email lookup returned with errors: {data.get('message', 'Unknown error')}")
            
            search = IntelligenceSearch.objects.create(
                search_type='EMAIL',
                query=email,
                user=request.user,
                results=data,
                risk_score=data.get('reputation', {}).get('risk_score') if not data.get('error') else None,
                risk_level=data.get('security', {}).get('risk_level') if not data.get('error') else 'Unknown',
                is_high_risk=data.get('security', {}).get('risk_score', 0) >= 6 if not data.get('error') else False
            )
            
            result = {
                'id': search.id,
                'search_type': 'EMAIL',
                'query': email,
                'risk_level': search.risk_level,
                'results': data,
                'timestamp': search.timestamp,
                'source': service_used,
                'is_fallback': data.get('is_fallback', False)
            }
            
            if data.get('is_fallback'):
                messages.info(request, f"Using free APIs for Email lookup (IPQS unavailable or failed)")
            else:
                messages.success(request, f"Email lookup completed for {email}")
            
        except Exception as e:
            messages.error(request, f"Email lookup failed: {str(e)}")
    
    context = {
        'form': form,
        'result': result,
        'service_used': service_used,
        'active_tab': 'email',
    }
    return render(request, 'intelligence/email_lookup.html', context)


@login_required
def phone_lookup(request):
    """Phone intelligence lookup with fallback to free APIs"""
    form = PhoneLookupForm(request.POST or None)
    result = None
    service_used = None
    
    if request.method == 'POST' and form.is_valid():
        phone = form.cleaned_data['phone_number']
        country_code = form.cleaned_data.get('country_code', 'auto')
        
        try:
            service = IntelligenceService(user=request.user)
            data = service.phone_lookup(phone, country_code=country_code)
            service_used = data.get('source', 'Unknown')
            
            if data.get('error'):
                messages.warning(request, f"Phone lookup returned with errors: {data.get('message', 'Unknown error')}")
            
            search = IntelligenceSearch.objects.create(
                search_type='PHONE',
                query=phone,
                user=request.user,
                results=data,
                risk_score=data.get('risk', {}).get('risk_score') if not data.get('error') else None,
                risk_level=data.get('risk', {}).get('risk_level') if not data.get('error') else 'Unknown',
                is_high_risk=data.get('risk', {}).get('risk_score', 0) >= 6 if not data.get('error') else False
            )
            
            result = {
                'id': search.id,
                'search_type': 'PHONE',
                'query': phone,
                'risk_level': search.risk_level,
                'results': data,
                'timestamp': search.timestamp,
                'source': service_used,
                'is_fallback': data.get('is_fallback', False)
            }
            
            if data.get('is_fallback'):
                messages.info(request, f"Using free APIs for Phone lookup (IPQS unavailable or failed)")
            else:
                messages.success(request, f"Phone lookup completed for {phone}")
            
        except Exception as e:
            messages.error(request, f"Phone lookup failed: {str(e)}")
    
    context = {
        'form': form,
        'result': result,
        'service_used': service_used,
        'active_tab': 'phone',
    }
    return render(request, 'intelligence/phone_lookup.html', context)


@login_required
def url_lookup(request):
    """URL/Domain intelligence lookup with fallback to free APIs"""
    form = URLLookupForm(request.POST or None)
    result = None
    service_used = None
    
    if request.method == 'POST' and form.is_valid():
        url = form.cleaned_data['url']
        
        try:
            service = IntelligenceService(user=request.user)
            data = service.url_lookup(url)
            service_used = data.get('source', 'Unknown')
            
            if data.get('error'):
                messages.warning(request, f"URL lookup returned with errors: {data.get('message', 'Unknown error')}")
            
            search = IntelligenceSearch.objects.create(
                search_type='URL',
                query=url,
                user=request.user,
                results=data,
                risk_score=data.get('reputation', {}).get('risk_score') if not data.get('error') else None,
                risk_level=data.get('reputation', {}).get('risk_level') if not data.get('error') else 'Unknown',
                is_high_risk=data.get('reputation', {}).get('risk_score', 0) >= 6 if not data.get('error') else False
            )
            
            result = {
                'id': search.id,
                'search_type': 'URL',
                'query': url,
                'risk_level': search.risk_level,
                'results': data,
                'timestamp': search.timestamp,
                'source': service_used,
                'is_fallback': data.get('is_fallback', False)
            }
            
            if data.get('is_fallback'):
                messages.info(request, f"Using free APIs for URL lookup (IPQS unavailable or failed)")
            else:
                messages.success(request, f"URL lookup completed for {url}")
            
        except Exception as e:
            messages.error(request, f"URL lookup failed: {str(e)}")
    
    context = {
        'form': form,
        'result': result,
        'service_used': service_used,
        'active_tab': 'url',
    }
    return render(request, 'intelligence/url_lookup.html', context)


@login_required
def breach_lookup(request):
    """Breach intelligence lookup with fallback to free APIs"""
    form = BreachLookupForm(request.POST or None)
    result = None
    service_used = None
    
    if request.method == 'POST' and form.is_valid():
        search_type = form.cleaned_data['search_type']
        query = form.cleaned_data['query']
        
        try:
            service = IntelligenceService(user=request.user)
            
            if search_type == 'email':
                data = service.breach_lookup(email=query)
            elif search_type == 'username':
                data = service.breach_lookup(username=query)
            elif search_type == 'phone':
                data = service.breach_lookup(phone=query)
            else:
                raise ValueError("Invalid search type")
            
            service_used = data.get('source', 'Unknown')
            
            if data.get('error'):
                messages.warning(request, f"Breach lookup returned with errors: {data.get('message', 'Unknown error')}")
            
            search = IntelligenceSearch.objects.create(
                search_type='BREACH',
                query=query,
                user=request.user,
                results=data,
                risk_score=10 if data.get('total_breaches', 0) > 0 else 0,
                risk_level=data.get('risk_level', 'Unknown'),
                is_high_risk=data.get('total_breaches', 0) > 0
            )
            
            result = {
                'id': search.id,
                'search_type': 'BREACH',
                'query': query,
                'risk_level': search.risk_level,
                'results': data,
                'timestamp': search.timestamp,
                'source': service_used,
                'is_fallback': data.get('is_fallback', False)
            }
            
            if data.get('is_fallback'):
                messages.info(request, f"Using free APIs for Breach lookup (IPQS unavailable or failed)")
            else:
                messages.success(request, f"Breach lookup completed for {query}")
            
        except Exception as e:
            messages.error(request, f"Breach lookup failed: {str(e)}")
    
    context = {
        'form': form,
        'result': result,
        'service_used': service_used,
        'active_tab': 'breach',
    }
    return render(request, 'intelligence/breach_lookup.html', context)


# ============================================
# SEARCH HISTORY VIEWS
# ============================================

@login_required
def search_history(request):
    """View search history with filtering"""
    search_type = request.GET.get('search_type', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    risk_level = request.GET.get('risk_level', '')
    
    searches = IntelligenceSearch.objects.filter(user=request.user)
    
    if search_type:
        searches = searches.filter(search_type=search_type)
    if date_from:
        searches = searches.filter(timestamp__gte=date_from)
    if date_to:
        searches = searches.filter(timestamp__lte=date_to)
    if risk_level:
        searches = searches.filter(risk_level=risk_level)
    
    paginator = Paginator(searches, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'search_type': search_type,
        'date_from': date_from,
        'date_to': date_to,
        'risk_level': risk_level,
        'search_types': IntelligenceSearch.SEARCH_TYPES,
        'risk_levels': ['Low', 'Medium', 'High', 'Critical'],
        'active_tab': 'history',
    }
    return render(request, 'intelligence/search_history.html', context)


@login_required
def search_detail(request, search_id):
    """View detailed search result"""
    search = get_object_or_404(IntelligenceSearch, id=search_id, user=request.user)
    
    source = search.results.get('source', 'Unknown')
    is_fallback = search.results.get('is_fallback', False)
    
    context = {
        'search': search,
        'source': source,
        'is_fallback': is_fallback,
        'active_tab': 'history',
    }
    return render(request, 'intelligence/search_detail.html', context)


# ============================================
# REPORT VIEWS
# ============================================

@login_required
def generate_report(request, search_id):
    """Generate report for a search"""
    search = get_object_or_404(IntelligenceSearch, id=search_id, user=request.user)
    
    if request.method == 'POST':
        format_type = request.POST.get('format', 'PDF')
        
        try:
            search_data = {
                'id': search.id,
                'search_type': search.get_search_type_display(),
                'query': search.query,
                'risk_level': search.risk_level,
                'results': search.results,
                'timestamp': search.timestamp,
                'source': search.results.get('source', 'Unknown')
            }
            
            report = ReportGenerator.save_report(search_data, request.user, format_type)
            
            messages.success(request, f"Report generated successfully in {format_type} format")
            return redirect('intelligence:download_report', report_id=report.id)
            
        except Exception as e:
            messages.error(request, f"Report generation failed: {str(e)}")
    
    context = {
        'search': search,
        'active_tab': 'history',
    }
    return render(request, 'intelligence/generate_report.html', context)


@login_required
def download_report(request, report_id):
    """Download generated report - FIXED"""
    report = get_object_or_404(IntelligenceReport, id=report_id, user=request.user)
    
    # Increment download count
    report.download_count += 1
    report.save()
    
    # Get file path - using settings.MEDIA_ROOT properly
    file_path = os.path.join(settings.MEDIA_ROOT, report.file_path)
    
    if not os.path.exists(file_path):
        messages.error(request, "Report file not found")
        return redirect('intelligence:search_history')
    
    # Determine content type
    content_types = {
        'PDF': 'application/pdf',
        'CSV': 'text/csv',
        'JSON': 'application/json',
    }
    
    with open(file_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type=content_types.get(report.report_format, 'application/octet-stream'))
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
        return response


# ============================================
# SETTINGS VIEWS
# ============================================

@login_required
@admin_required
def settings(request):
    """API settings view"""
    config = APIConfiguration.objects.first()
    form = APISettingsForm(request.POST or None, initial={
        'is_enabled': config.is_enabled if config else True
    })
    
    if request.method == 'POST' and form.is_valid():
        api_key = form.cleaned_data['api_key']
        is_enabled = form.cleaned_data['is_enabled']
        test_connection = form.cleaned_data.get('test_connection', False)
        
        # Encrypt API key
        if settings.FERNET:
            try:
                encrypted_key = settings.FERNET.encrypt(api_key.encode()).decode()
            except Exception as e:
                messages.error(request, f"Failed to encrypt API key: {str(e)}")
                encrypted_key = api_key
        else:
            encrypted_key = api_key
        
        # Create or update config
        if config:
            config.api_key = encrypted_key
            config.is_enabled = is_enabled
            config.updated_by = request.user
            config.save()
        else:
            config = APIConfiguration.objects.create(
                api_key=encrypted_key,
                is_enabled=is_enabled,
                updated_by=request.user
            )
        
        # Log configuration change
        APIAuditLog.objects.create(
            user=request.user,
            action='CONFIG_UPDATE',
            details={'is_enabled': is_enabled},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, "API configuration updated successfully")
        
        # Test connection if requested
        if test_connection:
            service = IntelligenceService(user=request.user)
            test_result = service.test_connection()
            
            config.last_test = timezone.now()
            config.test_status = test_result.get('success', False)
            config.test_message = test_result.get('message', '')
            config.save()
            
            if test_result.get('success'):
                messages.success(request, "API connection test successful")
            else:
                messages.error(request, f"API connection test failed: {test_result.get('message', 'Unknown error')}")
        
        return redirect('intelligence:settings')
    
    context = {
        'form': form,
        'config': config,
        'active_tab': 'settings',
    }
    return render(request, 'intelligence/settings.html', context)


@login_required
@admin_required
def test_api(request):
    """Test API connection with fallback"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        service = IntelligenceService(user=request.user)
        result = service.test_connection()
        
        config = APIConfiguration.objects.first()
        if config:
            config.last_test = timezone.now()
            config.test_status = result.get('success', False)
            config.test_message = result.get('message', '')
            config.save()
        
        APIAuditLog.objects.create(
            user=request.user,
            action='CONFIG_TEST',
            details=result,
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        return JsonResponse(result)
        
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)


@login_required
@admin_required
def audit_log(request):
    """View audit log"""
    logs = APIAuditLog.objects.select_related('user').all()
    
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'active_tab': 'settings',
    }
    return render(request, 'intelligence/audit_log.html', context)


# ============================================
# API VIEWS (for external use)
# ============================================

@login_required
def api_lookup(request):
    """REST API endpoint for lookups with fallback"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    lookup_type = request.POST.get('type')
    query = request.POST.get('query')
    
    if not lookup_type or not query:
        return JsonResponse({'error': 'Type and query are required'}, status=400)
    
    try:
        service = IntelligenceService(user=request.user)
        
        if lookup_type == 'IP':
            result = service.ip_lookup(query)
        elif lookup_type == 'EMAIL':
            result = service.email_lookup(query)
        elif lookup_type == 'PHONE':
            result = service.phone_lookup(query)
        elif lookup_type == 'URL':
            result = service.url_lookup(query)
        elif lookup_type == 'BREACH':
            result = service.breach_lookup(query)
        else:
            return JsonResponse({'error': 'Invalid lookup type'}, status=400)
        
        return JsonResponse(result)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)