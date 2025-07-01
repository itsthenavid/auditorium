from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.urls import resolve
from django import forms
from django.core.cache import cache

from .models import IndexPage

# Register your models here.


class IndexPageAdminForm(forms.ModelForm):
    """
    Custom form to handle title and description for the current language.
    """
    title = forms.CharField(
        label=_("Title"),
        required=False,
        help_text=_("Title in the current language.")
    )
    description = forms.CharField(
        label=_("Description"),
        widget=forms.Textarea,
        required=False,
        help_text=_("Description in the current language.")
    )

    class Meta:
        model = IndexPage
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang_code = self.get_lang_code_from_request()
        # Try to get from cache
        cache_key = f"index_page_content_{self.instance.id}_{lang_code}"
        content = cache.get(cache_key)
        if content is None:
            content = self.instance.content or {}
            cache.set(cache_key, content, timeout=3600)  # Cache for 1 hour
        self.initial['title'] = content.get(lang_code, {}).get('title', '')
        self.initial['description'] = content.get(lang_code, {}).get('description', '')

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
        Save title and description to the content JSONField for the current language.
        """
        instance = super().save(commit=False)
        lang_code = self.get_lang_code_from_request()
        # Update content JSON
        content = instance.content or {}
        content[lang_code] = {
            'title': self.cleaned_data['title'],
            'description': self.cleaned_data['description']
        }
        instance.content = content
        if commit:
            instance.save()
            # Update cache
            cache_key = f"index_page_content_{instance.id}_{lang_code}"
            cache.set(cache_key, content, timeout=3600)
        return instance

@admin.register(IndexPage)
class IndexPageAdmin(admin.ModelAdmin):
    """
    Custom admin for IndexPage model to manage content and image.
    """
    form = IndexPageAdminForm
    list_display = ('get_title', 'is_active', 'display_image')
    list_filter = ('is_active',)
    search_fields = ('content__en__title', 'content__fa__title', 'content__ckb__title', 'content__ku__title',
                     'content__en__description', 'content__fa__description', 'content__ckb__description', 'content__ku__description')
    fieldsets = (
        (None, {
            'fields': ('image', 'is_active')
        }),
        (_('Content'), {
            'fields': ('title', 'description')
        }),
    )

    def get_title(self, obj):
        """
        Display the title for the current language in the list view.
        """
        content = obj.content or {}
        for lang in ['en', 'fa', 'ckb', 'ku']:
            if lang in content and 'title' in content[lang]:
                return content[lang]['title']
        return "-"
    get_title.short_description = _("Title")

    def display_image(self, obj):
        """
        Display the index page image in the admin list view.
        """
        if obj.image and hasattr(obj.image, 'url'):
            return format_html('<img src="{}" style="width: 50px; height: 50px; object-fit: cover;" />', obj.image.url)
        return "-"
    display_image.short_description = _("Image")

    def get_form(self, request, obj=None, **kwargs):
        """
        Pass the request to the form to get the current language.
        """
        form = super().get_form(request, obj, **kwargs)
        form.request = request  # Attach request to the form
        return form

    def save_model(self, request, obj, form, change):
        """
        Save the model and ensure only one IndexPage is active.
        """
        super().save_model(request, obj, form, change)
