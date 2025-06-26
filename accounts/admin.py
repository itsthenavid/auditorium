from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django import forms

from django.utils.translation import gettext_lazy as _

from .models import User, UserProfileI18n

# Register your models here.
