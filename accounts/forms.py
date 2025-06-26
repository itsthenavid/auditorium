from django import forms
from django.utils.translation import gettext_lazy as _
from django.urls import resolve

from .models import User

# Create your forms here.


class UserAdminForm(forms.ModelForm):
    """
    Custom form to handle name and bio for the current language.
    """
    name = forms.CharField(
        label=_("Name"),
        required=False,
        help_text=_("User's name in the current language.")
    )
    bio = forms.CharField(
        label=_("Bio"),
        widget=forms.Textarea,
        required=False,
        help_text=_("User's bio in the current language.")
    )

    class Meta:
        model = User
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang_code = self.get_lang_code_from_request()
        # Load name and bio for the current language
        profiles = self.instance.profiles or {}
        self.initial['name'] = profiles.get(lang_code, {}).get('name', '')
        self.initial['bio'] = profiles.get(lang_code, {}).get('bio', '')

    def get_lang_code_from_request(self):
        """
        Extract the language code from the URL or request.LANGUAGE_CODE.
        """
        request = self.request
        resolver_match = resolve(request.path)
        lang_code = resolver_match.kwargs.get('lang_code', None)
        if not lang_code:
            lang_code = getattr(request, 'LANGUAGE_CODE', 'en')
        valid_langs = ['en', 'fa', 'ckb', 'ku']
        return lang_code if lang_code in valid_langs else 'en'

    def save(self, commit=True):
        """
        Save name and bio to the profiles JSONField for the current language.
        """
        instance = super().save(commit=False)
        lang_code = self.get_lang_code_from_request()
        # Update profiles JSON
        profiles = instance.profiles or {}
        profiles[lang_code] = {
            'name': self.cleaned_data['name'],
            'bio': self.cleaned_data['bio']
        }
        instance.profiles = profiles
        if commit:
            instance.save()
        return instance
