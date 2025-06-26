from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser
from random import choice

# Create your models here.

def _set_user_random_avatar():
    """
    Placeholder function to set a random avatar for the user.
    This can be implemented later to assign a random avatar from a predefined list.
    """
    # Logic to select a random avatar from a predefined list or directory
    avatars = [f"avatar{i}.webp" for i in range(1, 21)]

    return choice(avatars)


class User(AbstractUser):
    """
    Custom user model that extends the default Django user model.
    This model helps to maintain compatibility with the default user model
    while allowing for future extensions and customizations.
    This allows for additional fields and customization in the future.
    Also, it is necessary to set AUTH_USER_MODEL in settings.py to 'accounts.User'.
    """
    # Add any additional fields here if needed
    # For example:
    # bio = models.TextField(blank=True, null=True)

    avatar = models.ImageField(
        default=f"defaults/avatars/{_set_user_random_avatar()}",
        verbose_name=_("Avatar"),
        upload_to="avatars/",
        help_text=_("Upload a profile picture for the user."),
    )
    banner = models.ImageField(
        default="defaults/banners/default_banner.webp",
        verbose_name=_("Banner"),
        upload_to="banners/",
        help_text=_("Upload a banner image for the user profile."),
    )
    
    def __str__(self):
        return self.username
    

class UserProfileI18n(models.Model):
    """
    User profile model for internationalization (i18n).
    This model allows users to have profiles in multiple languages.
    It includes fields for language code, name, and bio.
    """
    # Language choices for the user profile
    LANG_CHOICES = [
        ('en', _('English')),
        ('fa', _('Persian (Farsi)')),
        ('ckb', _('Central Kurdish (Sorani Kurdish)')),
        ('ku', _('Northern Kurdish (Kurmanji Kurdish)')),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="i18n_profiles")
    lang_code = models.CharField(max_length=35, choices=LANG_CHOICES)

    name = models.CharField(max_length=255, blank=True)
    bio = models.TextField(blank=True)

    # Searchable fields
    # name_vec = VectorField(dimensions=768, null=True, blank=True)
    # bio_vec = VectorField(dimensions=768, null=True, blank=True)
    # bio_tsv = models.SearchVectorField(null=True)

    class Meta:
        unique_together = [("user", "lang_code")]
