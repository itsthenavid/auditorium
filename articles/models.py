from django.db import models
from django.utils.translation import gettext_lazy as _

# Create your models here.


class Category(models.Model):
    name = models.CharField(
        _("Category Name"),
        max_length=225
    )
    slug = models.SlugField(
        _("Category Slug"),
        max_length=55,
        unique=True
    )
    description = models.CharField(
        _("Category Description"),
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
