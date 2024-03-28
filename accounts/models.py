from django.db import models
from django.utils.translation import gettext_lazy as _
from random import choice

from django.contrib.auth.models import AbstractUser

# Create your models here.

def set_random_user_avatar():
    avatars = (
        "avatar_1",
        "avatar_2",
        "avatar_3",
        "avatar_4",
        "avatar_5",
        "avatar_6",
        "avatar_7",
        "avatar_8",
        "avatar_9",
        "avatar_10",
        "avatar_11",
        "avatar_12",
        "avatar_13",
        "avatar_14",
        "avatar_15",
        "avatar_16",
        "avatar_17",
        "avatar_18",
        "avatar_19",
        "avatar_20",
    )

    return choice(avatars)


class CustomUser(AbstractUser):
    avatar = models.ImageField(
        _("Avatars"),
        upload_to="accounts/avatars/",
        default=f"defaults/{set_random_user_avatar}.webp"
    )
    bio = models.CharField(
        _("Biography"),
        max_length=525,
        blank=True,
        null=True
    )

    class Meta:
        # Ordering system
        ordering = ("is_active", "date_joined", )

        # Translation system
        verbose_name = _("User")
        verbose_name_plural = _("Users")
