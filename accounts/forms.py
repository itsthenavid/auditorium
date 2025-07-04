from django import forms
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.forms import UserChangeForm
import random

from allauth.account.forms import SignupForm

from .models import User

# Create your forms here.

class RegisterForm(SignupForm):
    """
    Custom signup form for allauth with multilingual name and bio support.
    Detects language from URL lang_code or request.LANGUAGE_CODE in save method.
    """
    avatar = forms.ImageField(
        label=_("Avatar"),
        required=False,
        help_text=_("Upload a profile picture or use the default random avatar.")
    )
    default_avatar = forms.CharField(
        widget=forms.HiddenInput(),
        required=False
    )
    name = forms.CharField(
        label=_("Name"),
        max_length=100,
        required=True
    )
    bio = forms.CharField(
        label=_("Bio"),
        widget=forms.Textarea,
        required=False
    )

    def __init__(self, *args, **kwargs):
        self.language = kwargs.pop('language', 'en')
        super().__init__(*args, **kwargs)
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if self.language not in valid_languages:
            self.language = 'en'
        self.fields['name'].label = _(f"Name ({self.get_language_display()})")
        self.fields['bio'].label = _(f"Bio ({self.get_language_display()})")

    def get_language_display(self):
        """Return the display name of the current language."""
        lang_map = {
            'en': 'English',
            'fa': 'Persian',
            'ckb': 'Central Kurdish',
            'ku': 'Northern Kurdish'
        }
        return lang_map.get(self.language, 'English')

    def clean(self):
        cleaned_data = super().clean()
        # Ensure avatar takes precedence over default_avatar
        if 'avatar' not in cleaned_data or not cleaned_data['avatar']:
            if not cleaned_data.get('default_avatar'):
                cleaned_data['default_avatar'] = f"/static/shared/avatars/avatar_{random.randint(1, 20)}.webp"
        else:
            cleaned_data['default_avatar'] = ''  # Clear default_avatar if avatar is provided
        return cleaned_data

    def save(self, request):
        user = super().save(request)
        language = self.language if self.language != 'en' else getattr(request, 'LANGUAGE_CODE', 'en')
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if language not in valid_languages:
            language = 'en'
        profiles = user.profiles or {}
        profiles[language] = {
            'name': self.cleaned_data['name'],
            'bio': self.cleaned_data['bio']
        }
        user.profiles = profiles
        # Prioritize avatar over default_avatar
        if self.cleaned_data.get('avatar'):
            user.avatar = self.cleaned_data['avatar']
        elif self.cleaned_data.get('default_avatar'):
            user.avatar = self.cleaned_data['default_avatar']
        user.save()
        print("Saved user avatar:", user.avatar)  # Debug log
        return user


class CustomUserChangeForm(UserChangeForm):
    """
    Form for updating an existing user with multilingual name and bio support.
    Detects language from URL lang_code or request.LANGUAGE_CODE.
    """
    avatar = forms.ImageField(
        label=_("Avatar"),
        required=False,
        help_text=_("Upload a profile picture or use the default random avatar.")
    )
    default_avatar = forms.CharField(
        widget=forms.HiddenInput(),
        required=False
    )
    name = forms.CharField(
        label=_("Name"),
        max_length=100,
        required=True
    )
    bio = forms.CharField(
        label=_("Bio"),
        widget=forms.Textarea,
        required=False
    )

    class Meta:
        model = User
        fields = ('avatar', 'default_avatar', 'username', 'email', 'name', 'bio')

    def __init__(self, *args, **kwargs):
        self.language = kwargs.pop('language', 'en')
        super().__init__(*args, **kwargs)
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if self.language not in valid_languages:
            self.language = 'en'
        self.fields['name'].label = _(f"Name ({self.get_language_display()})")
        self.fields['bio'].label = _(f"Bio ({self.get_language_display()})")
        if self.instance and self.instance.profiles:
            profiles = self.instance.profiles
            self.initial['name'] = profiles.get(self.language, {}).get('name', '')
            self.initial['bio'] = profiles.get(self.language, {}).get('bio', '')
            self.initial['default_avatar'] = self.instance.avatar if self.instance.avatar else f"/static/shared/avatars/avatar_{random.randint(1, 20)}.webp"

    def get_language_display(self):
        """Return the display name of the current language."""
        lang_map = {
            'en': 'English',
            'fa': 'Persian',
            'ckb': 'Central Kurdish',
            'ku': 'Northern Kurdish'
        }
        return lang_map.get(self.language, 'English')

    def clean(self):
        cleaned_data = super().clean()
        # Ensure avatar takes precedence over default_avatar
        if 'avatar' not in cleaned_data or not cleaned_data['avatar']:
            if not cleaned_data.get('default_avatar'):
                cleaned_data['default_avatar'] = self.instance.avatar if self.instance.avatar else f"/static/shared/avatars/avatar_{random.randint(1, 20)}.webp"
        else:
            # Clear default_avatar if avatar is provided
            cleaned_data['default_avatar'] = ''
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        profiles = user.profiles or {}
        profiles[self.language] = {
            'name': self.cleaned_data['name'],
            'bio': self.cleaned_data['bio']
        }
        user.profiles = profiles
        # Prioritize avatar over default_avatar
        if self.cleaned_data.get('avatar'):
            user.avatar = self.cleaned_data['avatar']
        elif self.cleaned_data.get('default_avatar'):
            user.avatar = self.cleaned_data['default_avatar']
        if commit:
            user.save()
        # Debug log
        print("Saved user avatar:", user.avatar) 
        return user
