from django import forms
from django.core.validators import validate_email, URLValidator
from django.core.exceptions import ValidationError
import re

class IPLookupForm(forms.Form):
    ip_address = forms.CharField(
        max_length=45,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter IPv4 or IPv6 address...',
            'aria-label': 'IP Address'
        }),
        help_text="Enter a valid IPv4 or IPv6 address"
    )
    strictness = forms.ChoiceField(
        choices=[(0, 'Low'), (1, 'Medium'), (2, 'High'), (3, 'Very High')],
        initial=1,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    fast = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

class EmailLookupForm(forms.Form):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter email address...',
            'aria-label': 'Email Address'
        }),
        help_text="Enter a valid email address"
    )

class PhoneLookupForm(forms.Form):
    phone_number = forms.CharField(
        max_length=20,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter phone number with country code...',
            'aria-label': 'Phone Number'
        }),
        help_text="Enter phone number with country code (e.g., +1234567890)"
    )
    country_code = forms.CharField(
        max_length=5,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Country code (optional)',
            'aria-label': 'Country Code'
        }),
        help_text="Optional: Enter 2-letter country code"
    )

class URLLookupForm(forms.Form):
    url = forms.CharField(
        max_length=500,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter URL or domain...',
            'aria-label': 'URL/Domain'
        }),
        help_text="Enter a full URL or domain name (e.g., https://example.com)"
    )
    
    def clean_url(self):
        url = self.cleaned_data.get('url')
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        try:
            URLValidator()(url)
        except ValidationError:
            raise ValidationError("Invalid URL format")
        return url

class BreachLookupForm(forms.Form):
    SEARCH_TYPES = [
        ('email', 'Email Address'),
        ('username', 'Username'),
        ('phone', 'Phone Number'),
    ]
    
    search_type = forms.ChoiceField(
        choices=SEARCH_TYPES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    query = forms.CharField(
        max_length=255,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter email, username, or phone...',
            'aria-label': 'Search Query'
        })
    )

class APISettingsForm(forms.Form):
    api_key = forms.CharField(
        max_length=255,
        required=True,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your IPQualityScore API key'
        }),
        help_text="Get your API key from IPQualityScore dashboard"
    )
    is_enabled = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    test_connection = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )