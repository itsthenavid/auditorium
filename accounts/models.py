from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.validators import UnicodeUsernameValidator

from random import choice

from django.contrib.auth.models import AbstractUser

# Create your models here.

def _set_random_avatar():
    """
    Function to set a random avatar for the user.
    This function can be customized to select a random avatar
    from a predefined list or any other logic as per your requirement.
    """

    choices = (
        "defaults/accounts/avatars/avatar_1.webp",
        "defaults/accounts/avatars/avatar_2.webp",
        "defaults/accounts/avatars/avatar_3.webp",
        "defaults/accounts/avatars/avatar_4.webp",
        "defaults/accounts/avatars/avatar_5.webp",
        "defaults/accounts/avatars/avatar_6.webp",
        "defaults/accounts/avatars/avatar_7.webp",
        "defaults/accounts/avatars/avatar_8.webp",
        "defaults/accounts/avatars/avatar_9.webp",
        "defaults/accounts/avatars/avatar_10.webp",
    )
    
    # Example logic: return a default avatar URL
    return choice(choices)


class UserModel(AbstractUser):
    """
    Custom user model that extends the AbstractUser model.
    This model can be used to add additional fields or methods
    specific to your application's user requirements.
    """

    # Removing unnecessary fields
    first_name = None
    last_name = None
    
    # Add any additional fields or methods here
    # For example, you can add a profile picture field:
    # profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    
    name = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name=_("Name"),
        help_text=_("Enter your full name."),
    )
    avatar = models.ImageField(
        upload_to='avatars/',
        blank=True,
        null=True,
        default=_set_random_avatar,
        verbose_name=_("Avatar"),
        help_text=_("Select an avatar for your profile."),
    )
    bio = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        verbose_name=_("Bio"),
        help_text=_("Write a short bio about yourself."),
    )

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")

    def __str__(self):
        return self.username
    
    def __repr__(self):
        return self.username

    def __unicode__(self):
        return self.username
