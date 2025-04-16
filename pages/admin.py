from django.contrib import admin

from parler.admin import TranslatableAdmin

from .models import Page, Sentences

# Register your models here.


@admin.register(Page)
class PageAdmin(TranslatableAdmin):
    pass


@admin.register(Sentences)
class SentencesAdmin(TranslatableAdmin):
    """
    Admin interface for the Sentences model.
    """
    pass
