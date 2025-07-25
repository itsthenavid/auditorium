from django import forms
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.forms import UserChangeForm
import random
import os
from django.core.files import File
from django.conf import settings

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
        if 'avatar' not in cleaned_data or not cleaned_data['avatar']:
            if not cleaned_data.get('default_avatar'):
                cleaned_data['default_avatar'] = f"/static/shared/avatars/avatar_{random.randint(1, 20)}.webp"
        else:
            cleaned_data['default_avatar'] = ''
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
        if self.cleaned_data.get('avatar'):
            user.avatar = self.cleaned_data['avatar']
        elif self.cleaned_data.get('default_avatar'):
            user.avatar = self.cleaned_data['default_avatar']
        user.save()
        print("Saved user avatar:", user.avatar)
        return user


class ProfileImageForm(forms.ModelForm):
    """
    Form for editing user avatar and banner.
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
    banner = forms.ImageField(
        label=_("Banner"),
        required=False,
        help_text=_("Upload a banner image for the user profile.")
    )

    class Meta:
        model = User
        fields = ['avatar', 'banner']

    def clean(self):
        cleaned_data = super().clean()
        avatar = cleaned_data.get('avatar')
        default_avatar = cleaned_data.get('default_avatar')
        
        print(f"Cleaning form data: avatar={avatar}, default_avatar={default_avatar}")  # Debug
        
        # Prioritize default_avatar if provided
        if default_avatar:
            cleaned_data['avatar'] = default_avatar
        # If no avatar or default_avatar, set a random default
        elif not avatar and not default_avatar:
            cleaned_data['default_avatar'] = f"/static/shared/avatars/avatar_{random.randint(1, 20)}.webp"
            cleaned_data['avatar'] = cleaned_data['default_avatar']
        # If avatar is uploaded, clear default_avatar
        else:
            cleaned_data['default_avatar'] = ''
        
        print(f"Cleaned data: {cleaned_data}")  # Debug
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        avatar = self.cleaned_data.get('avatar')
        default_avatar = self.cleaned_data.get('default_avatar')
        banner = self.cleaned_data.get('banner')

        print(f"Saving form: avatar={avatar}, default_avatar={default_avatar}, banner={banner}")  # Debug

        # Handle default_avatar (static image path)
        if default_avatar and not avatar:
            # Convert static path to a File object
            static_path = default_avatar.lstrip('/static/')  # Remove '/static/' prefix
            full_path = os.path.join(settings.STATIC_ROOT, static_path)
            print(f"Looking for static file: {full_path}")  # Debug
            if os.path.exists(full_path):
                with open(full_path, 'rb') as f:
                    user.avatar.save(os.path.basename(full_path), File(f), save=False)
                print(f"Avatar set from default_avatar: {os.path.basename(full_path)}")  # Debug
            else:
                print(f"Warning: Static file {full_path} not found")  # Debug
        elif avatar:
            user.avatar = avatar
            print(f"Avatar set from uploaded file: {avatar}")  # Debug
        elif not avatar and not default_avatar:
            # Clear avatar if neither is provided
            user.avatar = None
            print("Avatar cleared")  # Debug

        if banner:
            user.banner = banner
            print(f"Banner set: {banner}")  # Debug

        if commit:
            user.save()
        return user


class ProfileInfoForm(forms.ModelForm):
    """
    Form for editing user username, name, email, and bio with multilingual support.
    Detects language from request.LANGUAGE_CODE in view.
    Profiles field is not exposed in UI to prevent direct access.
    """
    username = forms.CharField(
        label=_("Username"),
        max_length=150,
        required=True,
        help_text=_("Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.")
    )
    name = forms.CharField(
        label=_("Name"),
        max_length=100,
        required=False
    )
    email = forms.EmailField(
        label=_("Email"),
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
        fields = ['username', 'email']

    def __init__(self, *args, **kwargs):
        self.language = kwargs.pop('language', 'en')
        super().__init__(*args, **kwargs)
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if self.language not in valid_languages:
            self.language = 'en'
        self.fields['name'].label = _(f"Name ({self.get_language_display()})")
        self.fields['bio'].label = _(f"Bio ({self.get_language_display()})")
        
        # Populate name and bio from profiles JSONField
        if self.instance and self.instance.profiles:
            self.initial['name'] = self.instance.profiles.get(self.language, {}).get('name', '')
            self.initial['bio'] = self.instance.profiles.get(self.language, {}).get('bio', '')

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
        username = cleaned_data.get('username')
        email = cleaned_data.get('email')
        name = cleaned_data.get('name')
        bio = cleaned_data.get('bio')
        print(f"Cleaning info form: username={username}, email={email}, name={name}, bio={bio}")  # Debug
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        language = self.language
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if language not in valid_languages:
            language = 'en'
        
        # Update username and email
        user.username = self.cleaned_data['username']
        user.email = self.cleaned_data['email']
        
        # Update profiles JSONField for multilingual support
        profiles = user.profiles or {}
        profiles[language] = {
            'name': self.cleaned_data['name'],
            'bio': self.cleaned_data['bio']
        }
        user.profiles = profiles
        
        print(f"Saving info form: username={user.username}, email={user.email}, profiles={profiles}")  # Debug
        
        if commit:
            user.save()
        return user


class EmailVerificationForm(forms.Form):
    code = forms.CharField(max_length=10, label=_("Email Verify Code"))
