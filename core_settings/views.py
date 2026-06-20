from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.db.models import Count, Avg
from django.utils import timezone
from django.conf import settings
import json
from datetime import timedelta

from .models import APIService, APIUsageLog, APIAuditLog
from .forms import APIServiceForm


# ============================================
# API STATUS CHECK FUNCTIONS
# ============================================

def check_api_status(user):
    """Check the status of user's IPQS API key"""
    try:
        ipqs_service = APIService.objects.filter(
            user=user,
            service_type='IPQS'
        ).first()
        
        if not ipqs_service:
            return {
                'has_key': False,
                'is_enabled': False,
                'is_verified': False,
                'status': 'No API key configured',
                'status_class': 'inactive',
                'status_icon': 'fa-times-circle',
                'status_color': '#ff4757',
                'message': 'Please add your IPQualityScore API key in Settings → API Services'
            }
        
        if not ipqs_service.is_enabled:
            return {
                'has_key': True,
                'is_enabled': False,
                'is_verified': False,
                'service_name': ipqs_service.name,
                'service_type': ipqs_service.service_type,
                'status': 'API key is disabled',
                'status_class': 'inactive',
                'status_icon': 'fa-exclamation-triangle',
                'status_color': '#ffa502',
                'message': 'Your API key is currently disabled. Enable it to use intelligence features.'
            }
        
        if ipqs_service.is_verified and ipqs_service.last_verified:
            days_since_verify = (timezone.now() - ipqs_service.last_verified).days
            if days_since_verify <= 7:
                return {
                    'has_key': True,
                    'is_enabled': True,
                    'is_verified': True,
                    'service_name': ipqs_service.name,
                    'service_type': ipqs_service.service_type,
                    'last_verified': ipqs_service.last_verified,
                    'status': 'Connected',
                    'status_class': 'active',
                    'status_icon': 'fa-check-circle',
                    'status_color': '#00d4aa',
                    'message': f'API key verified on {ipqs_service.last_verified.strftime("%Y-%m-%d %H:%M")}'
                }
            else:
                return {
                    'has_key': True,
                    'is_enabled': True,
                    'is_verified': True,
                    'service_name': ipqs_service.name,
                    'service_type': ipqs_service.service_type,
                    'last_verified': ipqs_service.last_verified,
                    'status': 'Needs re-verification',
                    'status_class': 'warning',
                    'status_icon': 'fa-exclamation-triangle',
                    'status_color': '#ffa502',
                    'message': 'Your API key verification is older than 7 days. Please re-verify.'
                }
        
        return {
            'has_key': True,
            'is_enabled': True,
            'is_verified': False,
            'service_name': ipqs_service.name,
            'service_type': ipqs_service.service_type,
            'status': 'Not verified',
            'status_class': 'warning',
            'status_icon': 'fa-exclamation-triangle',
            'status_color': '#ffa502',
            'message': 'Your API key has not been verified. Click "Test Connection" to verify.'
        }
        
    except Exception as e:
        return {
            'has_key': False,
            'is_enabled': False,
            'is_verified': False,
            'status': f'Error: {str(e)}',
            'status_class': 'inactive',
            'status_icon': 'fa-times-circle',
            'status_color': '#ff4757',
            'message': f'Error checking API status: {str(e)}'
        }


# ============================================
# API SERVICES VIEWS
# ============================================

@login_required
def api_services(request):
    """View user's API services with status"""
    user = request.user
    
    # Get API status
    api_status = check_api_status(user)
    
    services = APIService.objects.filter(user=user).order_by('service_type')
    
    for service in services:
        service.usage_count = APIUsageLog.objects.filter(service=service, user=user).count()
        service.error_count = APIUsageLog.objects.filter(service=service, user=user, is_error=True).count()
        service.avg_response = APIUsageLog.objects.filter(service=service, user=user).aggregate(
            avg=Avg('response_time')
        )['avg'] or 0
    
    context = {
        'services': services,
        'api_status': api_status,
        'active_tab': 'api_services',
    }
    return render(request, 'core_settings/api_services.html', context)


@login_required
def api_service_create(request):
    """Create a new API service for the current user"""
    if request.method == 'POST':
        form = APIServiceForm(request.POST)
        if form.is_valid():
            service = form.save(commit=False)
            service.user = request.user
            service.save()
            
            # Try to verify the API key
            try:
                from intelligence.services.ipqs_service import IPQualityScoreService
                ipqs = IPQualityScoreService(user=request.user)
                test_result = ipqs.test_connection()
                
                if test_result.get('success'):
                    service.is_verified = True
                    service.last_verified = timezone.now()
                    service.save()
                    messages.success(
                        request, 
                        f'✅ API service "{service.name}" created and verified successfully!'
                    )
                else:
                    messages.warning(
                        request, 
                        f'⚠️ API service "{service.name}" created but verification failed. '
                        f'Please test the connection. Error: {test_result.get("message", "Unknown error")}'
                    )
            except Exception as e:
                messages.warning(
                    request, 
                    f'⚠️ API service "{service.name}" created but could not verify: {str(e)}'
                )
            
            # Log the creation
            APIAuditLog.objects.create(
                user=request.user,
                action='SERVICE_CREATE',
                details={
                    'service': service.name, 
                    'type': service.service_type,
                    'verified': service.is_verified
                },
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            return redirect('core_settings:api_services')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = APIServiceForm()
    
    context = {
        'form': form,
        'action': 'Create New Service',
        'active_tab': 'api_services',
    }
    return render(request, 'core_settings/api_service_form.html', context)


@login_required
def api_service_edit(request, service_id):
    """Edit a user's API service"""
    service = get_object_or_404(APIService, id=service_id, user=request.user)
    
    if request.method == 'POST':
        form = APIServiceForm(request.POST, instance=service)
        if form.is_valid():
            service = form.save(commit=False)
            
            # Check if API key changed
            old_service = APIService.objects.get(id=service_id)
            if old_service.api_key != service.api_key:
                service.is_verified = False
                service.last_verified = None
                
                # Try to verify new key
                try:
                    from intelligence.services.ipqs_service import IPQualityScoreService
                    ipqs = IPQualityScoreService(user=request.user)
                    test_result = ipqs.test_connection()
                    
                    if test_result.get('success'):
                        service.is_verified = True
                        service.last_verified = timezone.now()
                        messages.success(request, '✅ New API key verified successfully!')
                    else:
                        messages.warning(request, f'⚠️ New API key verification failed: {test_result.get("message", "Unknown error")}')
                except Exception as e:
                    messages.warning(request, f'⚠️ Could not verify new API key: {str(e)}')
            
            service.save()
            
            APIAuditLog.objects.create(
                user=request.user,
                action='SERVICE_UPDATE',
                details={
                    'service': service.name, 
                    'type': service.service_type,
                    'verified': service.is_verified
                },
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, f'API service "{service.name}" updated successfully')
            return redirect('core_settings:api_services')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = APIServiceForm(instance=service)
    
    context = {
        'form': form,
        'service': service,
        'action': f'Edit {service.name}',
        'active_tab': 'api_services',
    }
    return render(request, 'core_settings/api_service_form.html', context)


@login_required
def api_service_delete(request, service_id):
    """Delete a user's API service"""
    service = get_object_or_404(APIService, id=service_id, user=request.user)
    
    if request.method == 'POST':
        service_name = service.name
        
        APIAuditLog.objects.create(
            user=request.user,
            action='SERVICE_DELETE',
            details={'service': service_name, 'type': service.service_type},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        service.delete()
        messages.success(request, f'API service "{service_name}" deleted successfully')
        return redirect('core_settings:api_services')
    
    context = {
        'service': service,
        'active_tab': 'api_services',
    }
    return render(request, 'core_settings/api_service_delete.html', context)


@login_required
def api_service_test(request, service_id):
    """Test a user's API service connection"""
    service = get_object_or_404(APIService, id=service_id, user=request.user)
    test_result = None
    
    if request.method == 'POST':
        try:
            from intelligence.services.ipqs_service import IPQualityScoreService
            
            # Test with user's API key
            ipqs = IPQualityScoreService(user=request.user)
            
            # Log test attempt
            messages.info(request, f'🔍 Testing API connection for "{service.name}"...')
            
            result = ipqs.test_connection()
            
            if result.get('success'):
                service.is_verified = True
                service.last_verified = timezone.now()
                service.save()
                
                test_result = {
                    'success': True,
                    'message': f'✅ Successfully connected to {service.name}',
                    'details': result
                }
                messages.success(request, f'✅ API service "{service.name}" verified successfully!')
            else:
                service.is_verified = False
                service.save()
                
                error_msg = result.get('message', 'Connection failed')
                test_result = {
                    'success': False,
                    'message': f'❌ {service.name} test failed: {error_msg}',
                    'details': result
                }
                messages.error(request, f'❌ API service "{service.name}" test failed: {error_msg}')
            
            # Log the test
            APIAuditLog.objects.create(
                user=request.user,
                action='CONFIG_TEST',
                details={
                    'service': service.name,
                    'type': service.service_type,
                    'result': test_result.get('success', False),
                    'message': test_result.get('message', '')
                },
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
        except Exception as e:
            test_result = {
                'success': False,
                'message': f'❌ Error: {str(e)}',
                'details': {}
            }
            service.is_verified = False
            service.save()
            messages.error(request, f'❌ Error testing API: {str(e)}')
        
        return redirect('core_settings:api_services')
    
    context = {
        'service': service,
        'test_result': test_result,
        'active_tab': 'api_services',
    }
    return render(request, 'core_settings/api_service_test.html', context)


@login_required
def api_service_toggle(request, service_id):
    """Toggle user's API service enabled/disabled"""
    service = get_object_or_404(APIService, id=service_id, user=request.user)
    
    if request.method == 'POST':
        service.is_enabled = not service.is_enabled
        service.save()
        
        action = 'ENABLE' if service.is_enabled else 'DISABLE'
        APIAuditLog.objects.create(
            user=request.user,
            action=action,
            details={'service': service.name, 'enabled': service.is_enabled},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        status = 'enabled ✅' if service.is_enabled else 'disabled ❌'
        messages.success(request, f'API service "{service.name}" {status} successfully')
    
    return redirect('core_settings:api_services')


@login_required
def api_status_json(request):
    """Return API status as JSON"""
    status = check_api_status(request.user)
    return JsonResponse(status)


# ============================================
# API USAGE LOGS VIEWS
# ============================================

@login_required
def api_usage_logs(request):
    """View user's API usage logs"""
    user = request.user
    logs = APIUsageLog.objects.filter(user=user).select_related('service').all()
    
    service_id = request.GET.get('service')
    if service_id:
        logs = logs.filter(service_id=service_id)
    
    is_error = request.GET.get('is_error')
    if is_error:
        logs = logs.filter(is_error=is_error == 'true')
    
    date_from = request.GET.get('date_from')
    if date_from:
        logs = logs.filter(timestamp__gte=date_from)
    
    date_to = request.GET.get('date_to')
    if date_to:
        logs = logs.filter(timestamp__lte=date_to)
    
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    total_calls = APIUsageLog.objects.filter(user=user).count()
    error_count = APIUsageLog.objects.filter(user=user, is_error=True).count()
    avg_response_time = APIUsageLog.objects.filter(user=user).aggregate(
        avg=Avg('response_time')
    )['avg'] or 0
    success_rate = ((total_calls - error_count) / total_calls * 100) if total_calls > 0 else 0
    
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_calls = APIUsageLog.objects.filter(user=user, timestamp__gte=thirty_days_ago).count()
    
    user_services = APIService.objects.filter(user=user)
    
    context = {
        'page_obj': page_obj,
        'services': user_services,
        'total_calls': total_calls,
        'error_count': error_count,
        'avg_response_time': avg_response_time,
        'success_rate': success_rate,
        'recent_calls': recent_calls,
        'selected_service': service_id,
        'selected_error': is_error,
        'date_from': date_from,
        'date_to': date_to,
        'active_tab': 'api_usage',
    }
    return render(request, 'core_settings/api_usage_logs.html', context)


@login_required
def api_usage_clear(request):
    """Clear user's old API usage logs"""
    if request.method == 'POST':
        days = int(request.POST.get('days', 30))
        cutoff = timezone.now() - timedelta(days=days)
        
        deleted_count = APIUsageLog.objects.filter(user=request.user, timestamp__lt=cutoff).count()
        APIUsageLog.objects.filter(user=request.user, timestamp__lt=cutoff).delete()
        
        messages.success(request, f'🗑️ Deleted {deleted_count} old usage logs (older than {days} days)')
        return redirect('core_settings:api_usage_logs')
    
    return redirect('core_settings:api_usage_logs')


# ============================================
# AUDIT LOG VIEWS
# ============================================

@login_required
def audit_log(request):
    """View user's audit log"""
    user = request.user
    logs = APIAuditLog.objects.filter(user=user).all()
    
    action_type = request.GET.get('action')
    if action_type:
        logs = logs.filter(action=action_type)
    
    date_from = request.GET.get('date_from')
    if date_from:
        logs = logs.filter(timestamp__gte=date_from)
    
    date_to = request.GET.get('date_to')
    if date_to:
        logs = logs.filter(timestamp__lte=date_to)
    
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    action_types = APIAuditLog.ACTION_TYPES
    
    context = {
        'page_obj': page_obj,
        'action_types': action_types,
        'selected_action': action_type,
        'date_from': date_from,
        'date_to': date_to,
        'active_tab': 'audit_log',
    }
    return render(request, 'core_settings/audit_log.html', context)