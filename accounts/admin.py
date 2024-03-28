from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from django.utils.translation import gettext_lazy as _

from .models import CustomUser
from .forms import CustomUserCreationForm, CustomUserChangeForm

# Register your models here.


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser

    list_display = (
        "set_thumbnail_avatar",
        "get_user_suggested_name",
        "date_joined",
        "is_active",
        "is_staff",
        "is_superuser",
    )
    list_editable = (
        "is_active",
    )
    list_filter = (
        "is_active",
        "is_staff",
        "is_superuser",
        "date_joined",
    )
    list_per_page = 35
    search_fields = (
        "first_name",
        "last_name",
        "email",
        "username",
    )

    UserAdmin.add_fieldsets = (
        (
            None,
            {
                "fields": (
                    "avatar", 
                    "email", 
                    "username", 
                    "password1", 
                    "password2",
                ),
            },
        ),
        (_("Personal Info"), {"fields": ("first_name", "last_name", "bio", )}),
    )

    UserAdmin.fieldsets = (
        (None, {"fields": ("avatar", "email", "username", "password")}),
        (_("Personal info"), {"fields": ("first_name", "last_name", "bio", )}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )
