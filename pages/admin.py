from django.contrib import admin

from parler.admin import TranslatableAdmin

from .models import Page

# Register your models here.


@admin.register(Page)
class PageAdmin(TranslatableAdmin):
    pass
