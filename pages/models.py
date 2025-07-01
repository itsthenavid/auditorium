from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.db.models.signals import post_save
from django.dispatch import receiver

# Create your models here.

def _validate_content(value):
    if not isinstance(value, dict):
        raise ValidationError("Content must be a dictionary.")
    for lang, data in value.items():
        if lang not in ['en', 'fa', 'ckb', 'ku']:
            raise ValidationError(f"Invalid language code: {lang}")
        if not isinstance(data, dict) or 'title' not in data or 'description' not in data:
            raise ValidationError(f"Invalid content data for language {lang}")


class IndexPage(models.Model):
    content = models.JSONField(
        default=dict,
        verbose_name=_("Content"),
        help_text=_("Title and description for different languages, stored as JSON."),
        validators=[_validate_content]
    )
    image = models.ImageField(
        upload_to='pages/images/',
        verbose_name=_("Image"),
        help_text=_("Image for the index page.")
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name=_("Is Active"),
        help_text=_("Only one IndexPage can be active at a time.")
    )

    class Meta:
        verbose_name = _("Index Page")
        verbose_name_plural = _("Index Pages")

    def __str__(self):
        # Return title for the default language (en) or first available
        content = self.content or {}
        for lang in ['en', 'fa', 'ckb', 'ku']:
            if lang in content and 'title' in content[lang]:
                return content[lang]['title']
        return _("Index Page")
    
@receiver(post_save, sender=IndexPage)
def ensure_single_active_index_page(sender, instance, **kwargs):
    """
    Ensure only one IndexPage is active at a time.
    """
    if instance.is_active:
        IndexPage.objects.filter(is_active=True).exclude(pk=instance.pk).update(is_active=False)
