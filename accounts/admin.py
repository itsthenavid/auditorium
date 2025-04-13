from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .models import UserModel

# Register your models here.

@admin.register(UserModel)
class UserAdmin(admin.ModelAdmin):
    """
    Admin interface for the custom user model.
    This class can be used to customize the admin interface
    for the user model, including fields to display, filters, etc.
    """
    
    # List of fields to display in the admin list view
    list_display = ("email", "name", "is_staff", "is_active")
    
    # Fields to filter by in the admin list view
    list_filter = ("is_staff", "is_active")
    
    # Fields to search by in the admin list view
    search_fields = ("email", "name")
    
    # Fields to exclude from the admin form
    exclude = ("password",)
