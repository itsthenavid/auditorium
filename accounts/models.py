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
    avatars = (
        "avatar1.webp",
        "avatar2.webp",
        "avatar3.webp",
        "avatar4.webp",
        "avatar5.webp",
        "avatar6.webp",
        "avatar7.webp",
        "avatar8.webp",
        "avatar9.webp",
        "avatar10.webp",
        "avatar11.webp",
        "avatar12.webp",
        "avatar13.webp",
        "avatar14.webp",
        "avatar15.webp",
        "avatar16.webp",
        "avatar17.webp",
        "avatar18.webp",
        "avatar19.webp",
        "avatar20.webp",
    )

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
    bio = models.CharField(
        max_length=525,
        blank=True,
        null=True,
        verbose_name=_("Bio"),
        help_text=_("A short biography for the user."),
    )
    
    def __str__(self):
        return self.username
