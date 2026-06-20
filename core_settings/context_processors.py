# core_settings/context_processors.py
from .views import check_api_status

def api_status(request):
    """Add API status to all templates"""
    if request.user.is_authenticated:
        return {
            'api_status': check_api_status(request.user)
        }
    return {
        'api_status': {
            'has_key': False,
            'is_enabled': False,
            'is_verified': False,
            'status': 'Not logged in',
            'status_class': 'inactive'
        }
    }