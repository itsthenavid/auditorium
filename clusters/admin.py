from django.contrib import admin

from .models import Category, Article

# Register your models here.


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "is_active",
    )
    list_editable = (
        "is_active",
    )
    list_filter = (
        "is_active",
    )
    search_fields = (
        "name",
    )
    list_per_page = 35


@admin.register(Article)
class ArticleAdmin(admin.ModelAdmin):
    list_display = (
        "set_artwork_thumbnail",
        "title",
        "publish_datetime",
        "status",
        "author",
        "is_active",
        "category",
    )
    list_editable = (
        "status",
        "category",
    )
    list_filter = (
        "status",
        "category",
        "is_active",
        "publish_datetime",
    )
    list_per_page = 15
    search_fields = (
        "title",
        "description",
    )
