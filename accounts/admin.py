from django.contrib import admin
from django import forms
from django.utils.html import format_html
from django.urls import resolve

from django.utils.translation import gettext_lazy as _

from .models import User

# Register your models here.


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

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    """
    Custom admin for User model to display avatar, banner, name, and bio.
    """
    form = UserAdminForm
    list_display = ('username', 'email', 'display_avatar', 'is_active', 'date_joined')
    list_filter = ('is_active', 'is_staff', 'date_joined')
    search_fields = ('username', 'email', 'profiles__name', 'profiles__bio')
    fieldsets = (
        (None, {
            'fields': ('username', 'email', 'password')
        }),
        (_('Personal Info'), {
            'fields': ('first_name', 'last_name', 'avatar', 'banner', 'display_banner', 'name', 'bio')
        }),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
        (_('Important Dates'), {
            'fields': ('last_login', 'date_joined')
        }),
    )
    readonly_fields = ('display_banner',)

    def display_avatar(self, obj):
        """
        Display the user's avatar in the admin list view.
        """
        if obj.avatar and hasattr(obj.avatar, 'url'):
            return format_html('<img src="{}" style="width: 50px; height: 50px; object-fit: cover;" />', obj.avatar.url)
        return "-"
    display_avatar.short_description = _("Avatar")

    def display_banner(self, obj):
        """
        Display the user's banner in the admin change view.
        """
        if obj.banner and hasattr(obj.banner, 'url'):
            return format_html('<img src="{}" style="width: 100px; height: 50px; object-fit: cover;" />', obj.banner.url)
        return "-"
    display_banner.short_description = _("Banner")

    def get_form(self, request, obj=None, **kwargs):
        """
        Pass conftest.py
        Pass the request to the form to get the current language.
        """
        form = super().get_form(request, obj, **kwargs)
        form.request = request  # Attach request to the form
        return form
