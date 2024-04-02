from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils.timezone import now
from django.contrib.auth import get_user_model as _user_model
from django.utils.html import format_html

from django_ckeditor_5.fields import CKEditor5Field

# Create your models here.


class Category(models.Model):
    name = models.CharField(
        _("Name"),
        max_length=125
    )
    slug = models.SlugField(
        _("Slug"),
        max_length=55,
        unique=True
    )
    description = models.CharField(
        _("Description"),
        max_length=255,
        blank=True
    )
    datetime_created = models.DateTimeField(
        _("Datetime Created"),
        auto_now_add=True,
        db_index=True
    )
    datetime_modified = models.DateTimeField(
        _("Datetime Modified"),
        auto_now=True,
        db_index=True
    )
    is_active = models.BooleanField(
        _("Active"),
        default=False
    )

    class Meta:
        # Ordering system
        ordering = ("is_active", "-datetime_created", )

        # Translation system
        verbose_name = _("Category")
        verbose_name_plural = _("Categories")

        # Database management
        indexes = [
            models.Index(fields=[
                "datetime_created",
                "datetime_modified",
            ], )
        ]
    
    def __str__(self) -> str:
        return self.name
    
    def __repr__(self) -> str:
        return self.name
    

class Article(models.Model):
    STATUS_CHOICES = (
        (str(0), _("Draft"), ), 
        (str(1), _("Published"), )
    )

    artwork = models.ImageField(
        _("Artwork"),
        upload_to="articles/artworks/",
        default="constants/default_artwork.webp"
    )
    title = models.CharField(
        _("Title"),
        max_length=125
    )
    description = models.CharField(
        _("Description"),
        max_length=355,
        blank=True
    )
    datetime_created = models.DateTimeField(
        _("Datetime Created"),
        auto_now_add=True,
    )
    datetime_modified = models.DateTimeField(
        _("Datetime Modified"),
        auto_now=True,
    )
    slug = models.SlugField(
        _("Slug"),
        max_length=55
    )
    author = models.ForeignKey(
        verbose_name=_("Author"),
        to=_user_model(),
        on_delete=models.SET_NULL,
        null=True,
        related_name="user_articles",
        db_index=True
    )
    publish_datetime = models.DateTimeField(
        _("Publish Datetime"),
        default=now,
        blank=True,
        db_index=True
    )
    category = models.ForeignKey(
        verbose_name=_("Article Category"),
        to=Category,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="category_articles",
        db_index=True
    )
    content = CKEditor5Field(
        _("Content"),
        config_name="extends",
        blank=True
    )
    status = models.CharField(
        _("Status"),
        choices=STATUS_CHOICES,
        max_length=1,
        default=STATUS_CHOICES[0][0],
        db_index=True
    )
    is_active = models.BooleanField(
        _("Active"),
        default=True,
        db_index=True
    )

    class Meta:
        # Ordering system
        ordering = (
            "is_active",
            "-publish_datetime"
        )

        # Translation system
        verbose_name = _("Article")
        verbose_name_plural = _("Articles")

        # Database management system
        indexes = (
            models.Index(fields=[
                "author",
                "publish_datetime",
                "category",
                "status",
                "is_active",
            ], ), 
        )

    def set_artwork_thumbnail(self):
        return format_html(
            f"""
            <img src={self.artwork.url} style="width: 85px; height: 55px; border-radius: 5%;" />
            """
        )
    set_artwork_thumbnail.short_description = _("Artwork")

    def __str__(self) -> str:
        return self.title
    
    def __repr__(self) -> str:
        return self.title
