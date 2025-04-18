from django.contrib import admin

from .models import IPAddress

# Register your models here.


@admin.register(IPAddress)
class IPAddressAdmin(admin.ModelAdmin):
    """
    Admin class to manage the IPAddress model in the Django admin interface.
    This class is used to customize the admin interface for the IPAddress model.
    """

    list_display = ("ip_address", "created_at")
    search_fields = ("ip_address",)
    list_filter = ("created_at",)
