from django.contrib import admin
from django.utils.html import format_html

from django.utils.translation import gettext_lazy as _

from .models import User
# from .forms import UserAdminForm

# Register your models here.

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    """
    Custom admin for User model to display avatar, banner, name, and bio.
    """
    # form = UserAdminForm
    list_display = ('username', 'email', 'display_avatar', 'is_active', 'date_joined')
    list_filter = ('is_active', 'is_staff', 'date_joined')
    search_fields = ('username', 'email', 'profiles__name', 'profiles__bio')
    fieldsets = (
        (None, {
            'fields': ('username', 'email', 'password')
        }),
        (_('Personal Info'), {
            'fields': ('first_name', 'last_name', 'avatar', 'banner', 'display_banner', "is_verified", )
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
        # Attach request to the form
        form.request = request 
        return form
