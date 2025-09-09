from django.contrib import admin

from .models import Settings

# Register your models here.

@admin.register(Settings)
class SettingsAdmin(admin.ModelAdmin):
    list_display = ('user', 'language', 'theme')
    search_fields = ('user__username', 'language', 'theme')
    list_filter = ('language', 'theme')
