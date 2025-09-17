from django.contrib import admin
from django.utils.html import mark_safe
from django.utils.translation import gettext_lazy as _
from django.db.models import Prefetch

from tinymce.widgets import TinyMCE

from .models import (
    Topic, TopicTranslation, Post, PostTranslation, PostImage
)

# Register your models here.


# Inline for translations (stacked for better readability)
class TranslationInline(admin.StackedInline):
    """Base inline for translations with TinyMCE support."""
    fields = ('language', 'title', 'slug', 'excerpt', 'content')
    extra = 1  # One extra form by default
    can_delete = True
    show_change_link = True

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        """Override widget for HTML fields to use TinyMCE."""
        if db_field.name == 'content':
            kwargs['widget'] = TinyMCE(attrs={'cols': 80, 'rows': 30})
        return super().formfield_for_dbfield(db_field, request, **kwargs)


# Specific inline for PostTranslation
class PostTranslationInline(TranslationInline):
    model = PostTranslation
    prepopulated_fields = {'slug': ('title',)}  # Auto-populate slug from title


# Specific inline for TopicTranslation
class TopicTranslationInline(TranslationInline):
    model = TopicTranslation
    fields = ('language', 'title', 'slug')  # Topic has fewer fields
    prepopulated_fields = {'slug': ('title',)}


# Inline for PostImage with thumbnail preview
class PostImageInline(admin.TabularInline):
    """Inline for images with thumbnail display."""
    model = PostImage
    fields = ('image', 'caption', 'created_at', 'image_preview')
    readonly_fields = ('created_at', 'image_preview')
    extra = 3  # Allow up to 3 extra images by default
    can_delete = True
    show_change_link = True

    def image_preview(self, obj):
        """Display thumbnail of the image."""
        if obj.image:
            return mark_safe(
                f'<img src="{obj.image.url}" width="150" height="150" '
                'style="object-fit: contain;" />'
            )
        return _("No image uploaded")

    image_preview.short_description = _("Image Preview")


@admin.register(Topic)
class TopicAdmin(admin.ModelAdmin):
    """Admin for Topic model with translations inline."""
    list_display = (
        'get_title', 'name', 'datetime_created', 'datetime_modified'
    )
    search_fields = ('name', 'translations__title', 'translations__slug')
    list_filter = ('translations__language',)
    date_hierarchy = 'datetime_created'
    inlines = [TopicTranslationInline]
    readonly_fields = ('datetime_created', 'datetime_modified')
    fieldsets = (
        (None, {
            'fields': ('name', 'description')
        }),
        (_('Timestamps'), {
            'fields': ('datetime_created', 'datetime_modified'),
            'classes': ('collapse',)
        }),
    )

    def get_title(self, obj):
        """Display translated title in list view."""
        tr = obj.get_translation()
        return tr.title if tr else obj.name

    get_title.short_description = _("Title")

    def get_queryset(self, request):
        """Optimize queryset with prefetch for translations."""
        qs = super().get_queryset(request)
        return qs.prefetch_related('translations')


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    """Advanced admin for Post model with inlines and filters."""
    list_display = (
        'get_title', 'get_main_cover_preview', 'is_active',
        'datetime_published', 'datetime_created'
    )
    search_fields = (
        'translations__title', 'translations__slug', 'translations__excerpt'
    )
    list_filter = (
        'is_active', 'topics', 'translations__language', 'datetime_published'
    )
    date_hierarchy = 'datetime_published'
    inlines = [PostTranslationInline, PostImageInline]
    readonly_fields = (
        'datetime_created', 'datetime_modified', 'get_main_cover_preview'
    )
    fieldsets = (
        (None, {
            'fields': (
                'topics', 'datetime_published', 'is_active',
                'get_main_cover_preview'
            )
        }),
        (_('Timestamps'), {
            'fields': ('datetime_created', 'datetime_modified'),
            'classes': ('collapse',)
        }),
    )
    actions = ['make_active', 'make_inactive']

    def get_title(self, obj):
        """Display translated title in list view."""
        tr = obj.get_translation()
        return tr.title if tr else _("Untitled Post")

    get_title.short_description = _("Title")

    def get_main_cover_preview(self, obj):
        """Display thumbnail of main cover image."""
        main_cover = obj.main_cover
        if main_cover and main_cover.image:
            return mark_safe(
                f'<img src="{main_cover.image.url}" width="100" height="100" '
                'style="object-fit: contain;" />'
            )
        return _("No main cover")

    get_main_cover_preview.short_description = _("Main Cover Preview")

    def get_queryset(self, request):
        """Optimize with prefetch for translations and images."""
        qs = super().get_queryset(request)
        return qs.prefetch_related(
            Prefetch('translations'),
            Prefetch('images', queryset=PostImage.objects.order_by('created_at'))
        )

    def make_active(self, request, queryset):
        """Action to activate selected posts."""
        queryset.update(is_active=True)
        self.message_user(request, _("Selected posts activated."))

    make_active.short_description = _("Activate selected posts")

    def make_inactive(self, request, queryset):
        """Action to deactivate selected posts."""
        queryset.update(is_active=False)
        self.message_user(request, _("Selected posts deactivated."))

    make_inactive.short_description = _("Deactivate selected posts")


# Register other models if needed (translations as separate admins)
@admin.register(TopicTranslation)
class TopicTranslationAdmin(admin.ModelAdmin):
    """Admin for TopicTranslation."""
    list_display = ('title', 'language', 'topic', 'slug')
    search_fields = ('title', 'slug')
    list_filter = ('language',)


@admin.register(PostTranslation)
class PostTranslationAdmin(admin.ModelAdmin):
    """Admin for PostTranslation with TinyMCE."""
    list_display = ('title', 'language', 'post', 'slug')
    search_fields = ('title', 'slug', 'excerpt')
    list_filter = ('language',)

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        """Use TinyMCE for content field."""
        if db_field.name == 'content':
            kwargs['widget'] = TinyMCE(attrs={'cols': 80, 'rows': 30})
        return super().formfield_for_dbfield(db_field, request, **kwargs)


@admin.register(PostImage)
class PostImageAdmin(admin.ModelAdmin):
    """Admin for PostImage with preview."""
    list_display = ('post', 'caption', 'created_at', 'image_preview')
    search_fields = ('caption',)
    readonly_fields = ('created_at', 'image_preview')

    def image_preview(self, obj):
        """Display image thumbnail."""
        if obj.image:
            return mark_safe(
                f'<img src="{obj.image.url}" width="150" height="150" '
                'style="object-fit: contain;" />'
            )
        return _("No image")

    image_preview.short_description = _("Image Preview")
