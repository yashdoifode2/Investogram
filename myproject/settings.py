import os
from pathlib import Path
from decouple import config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost').split(',')

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
    'intelligence',  # Add this
    'crispy_forms',
    'crispy_bootstrap5',
    'core_settings',  # Add this
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'myproject.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'myproject.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Login/Logout URLs
# myproject/settings.py
# Change these lines:

LOGIN_URL = 'accounts:login'  # Changed from 'login'
LOGIN_REDIRECT_URL = 'accounts:dashboard'  # Changed from 'dashboard'
LOGOUT_REDIRECT_URL = 'accounts:login'  # Changed from 'login'

# Custom User Model
AUTH_USER_MODEL = 'accounts.CustomUser'

import os
from pathlib import Path
from decouple import config
from cryptography.fernet import Fernet

# ... existing settings ...

# ============================================
# IPQualityScore Configuration
# ============================================
IPQS_API_KEY = config('IPQS_API_KEY', default='')
IPQS_ENABLED = config('IPQS_ENABLED', default=True, cast=bool)
IPQS_TIMEOUT = config('IPQS_TIMEOUT', default=30, cast=int)
IPQS_MAX_RETRIES = config('IPQS_MAX_RETRIES', default=3, cast=int)
IPQS_RATE_LIMIT = config('IPQS_RATE_LIMIT', default=1000, cast=int)
IPQS_BASE_URL = 'https://ipqualityscore.com/api/json'

# Encryption
ENCRYPTION_KEY = config('ENCRYPTION_KEY', default='')
if ENCRYPTION_KEY:
    FERNET = Fernet(ENCRYPTION_KEY.encode())



# Crispy Forms
CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap5"
CRISPY_TEMPLATE_PACK = "bootstrap5"
