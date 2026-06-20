from django.shortcuts import redirect
from django.contrib import messages
from django.urls import reverse

def login_required_decorator(view_func):
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, 'Please login to access this page.')
            return redirect('accounts:login')
        return view_func(request, *args, **kwargs)
    return wrapper