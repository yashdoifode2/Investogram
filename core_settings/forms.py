from django import forms
from .models import APIService

class APIServiceForm(forms.ModelForm):
    """Form for creating/editing API services"""
    
    class Meta:
        model = APIService
        fields = [
            'name', 'service_type', 'api_key', 'base_url', 'is_enabled',
            'rate_limit', 'rate_limit_period', 'timeout', 'max_retries',
            'extra_config'
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter service name'
            }),
            'service_type': forms.Select(attrs={
                'class': 'form-select'
            }),
            'api_key': forms.PasswordInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter API key',
                'render_value': True
            }),
            'base_url': forms.URLInput(attrs={
                'class': 'form-control',
                'placeholder': 'https://api.example.com'
            }),
            'is_enabled': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'rate_limit': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 1
            }),
            'rate_limit_period': forms.Select(attrs={
                'class': 'form-select'
            }),
            'timeout': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 1,
                'max': 120
            }),
            'max_retries': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 0,
                'max': 10
            }),
            'extra_config': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': '{"key": "value"}'
            }),
        }
    
    def clean_extra_config(self):
        """Validate JSON format for extra_config"""
        data = self.cleaned_data.get('extra_config')
        if data:
            try:
                import json
                if isinstance(data, str):
                    return json.loads(data)
                return data
            except json.JSONDecodeError:
                raise forms.ValidationError('Invalid JSON format')
        return {}
    
    def clean_api_key(self):
        """Clean and validate API key"""
        api_key = self.cleaned_data.get('api_key')
        if not api_key:
            raise forms.ValidationError('API key is required')
        return api_key


class APIServiceTestForm(forms.Form):
    """Form for testing API connection"""
    
    test_endpoint = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '/test'
        }),
        help_text="Optional: Specific endpoint to test"
    )