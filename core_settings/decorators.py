from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps

def admin_required(view_func):
    """Decorator to restrict access to admin users only"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, 'Please login to access this page.')
            return redirect('accounts:login')
        
        if not request.user.is_staff and not request.user.is_superuser:
            messages.error(request, 'You do not have permission to access this page.')
            return redirect('core_settings:api_services')
        
        return view_func(request, *args, **kwargs)
    return wrapper