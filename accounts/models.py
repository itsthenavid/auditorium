from django.db import models
from django.utils.translation import gettext_lazy as _

from random import choice
from django.contrib.auth.models import AbstractUser
from django.utils.html import format_html

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
    email = models.EmailField(_("Email Address"), unique=True)
    avatar = models.ImageField(
        _("Avatar"),
        upload_to="accounts/avatars/",
        default=f"constants/{set_random_user_avatar()}.webp",
        blank=True
    )
    bio = models.CharField(
        _("Biography"),
        max_length=525,
        blank=True,
        null=True
    )

    class Meta:
        # Ordering system
        ordering = ("is_active", "-date_joined", )

        # Translation system
        verbose_name = _("User")
        verbose_name_plural = _("Users")
    
    def get_user_suggested_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.last_name:
            return f"{self.last_name}"
        elif self.first_name:
            return f"{self.first_name}"
        else:
            return f"{self.username}"
    get_user_suggested_name.short_description = _("User Name")
    
    def set_thumbnail_avatar(self):
        return format_html(
            f"""
            <img src="{self.avatar.url}" 
            style="height: 50px; width: 50px; border-radius: 50%;" />
            """
        )
    set_thumbnail_avatar.short_description = _("Avatar")
    
    def __str__(self):
        return self.get_user_suggested_name()
    
    def __repr__(self):
        return self.get_user_suggested_name()
