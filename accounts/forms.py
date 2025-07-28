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
                cleaned_data['default_avatar'] = f"{settings.STATIC_URL}shared/avatars/avatar_{random.randint(1, 20)}.webp"
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
        
        if default_avatar:
            cleaned_data['avatar'] = default_avatar
        elif not avatar and not default_avatar:
            cleaned_data['default_avatar'] = f"{settings.STATIC_URL}shared/avatars/avatar_{random.randint(1, 20)}.webp"
            cleaned_data['avatar'] = cleaned_data['default_avatar']
        else:
            cleaned_data['default_avatar'] = ''
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        avatar = self.cleaned_data.get('avatar')
        default_avatar = self.cleaned_data.get('default_avatar')
        banner = self.cleaned_data.get('banner')

        if default_avatar and not avatar:
            static_path = default_avatar.lstrip(settings.STATIC_URL)
            full_path = os.path.join(settings.STATIC_ROOT, static_path)
            if os.path.exists(full_path):
                with open(full_path, 'rb') as f:
                    user.avatar.save(os.path.basename(full_path), File(f), save=False)
            else:
                user.avatar = default_avatar
        elif avatar:
            user.avatar = avatar
        elif not avatar and not default_avatar:
            user.avatar = None

        if banner:
            user.banner = banner

        if commit:
            user.save()
        return user


class ProfileInfoForm(forms.ModelForm):
    """
    Form for editing user username, name, email, and bio with multilingual support.
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
        required=False
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

    def clean_bio(self):
        bio = self.cleaned_data.get('bio')
        if bio and len(bio) > 500:
            raise forms.ValidationError(_("Bio cannot exceed 500 characters."))
        return bio

    def save(self, commit=True):
        user = super().save(commit=False)
        language = self.language
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if language not in valid_languages:
            language = 'en'
        
        user.username = self.cleaned_data['username']
        if self.cleaned_data.get('email'):
            user.email = self.cleaned_data['email']
        
        profiles = user.profiles or {}
        profiles[language] = {
            'name': self.cleaned_data['name'],
            'bio': self.cleaned_data['bio']
        }
        user.profiles = profiles
        
        if commit:
            user.save()
        return user


class EmailVerificationForm(forms.Form):
    code = forms.CharField(
        max_length=10,
        min_length=10,
        label=_("Email Verify Code"),
        help_text=_("Enter the 10-digit verification code sent to your email.")
    )

    def clean_code(self):
        code = self.cleaned_data.get('code')
        if not code.isdigit():
            raise forms.ValidationError(_("The verification code must be exactly 10 digits."))
        return code
