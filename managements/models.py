from django.db import models
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.contrib.auth import get_user_model

# Create your models here.


class Settings(models.Model):
    LANGUAGE_CHOICES = settings.LANGUAGES
    THEME_CHOICES = (
        ('DA', _("Default Auto")),
        ('DL', _("Default Light")),
        ('DD', _("Default Dark")),
    )
    
    user = models.OneToOneField(
        verbose_name=_("User"),
        to=get_user_model(),
        on_delete=models.CASCADE,
        related_name='settings',
    )
    language = models.CharField(
        verbose_name=_("Language"),
        max_length=10,
        choices=LANGUAGE_CHOICES,
        default=settings.LANGUAGE_CODE,
    )
    theme = models.CharField(
        verbose_name=_("Theme"),
        max_length=20,
        choices=THEME_CHOICES,
        default=THEME_CHOICES[0][0],
    )

    def __str__(self):
        return self.language
