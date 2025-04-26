from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser, UserManager
from parler.models import TranslatableModel, TranslatedFields
from parler.managers import TranslatableManager, TranslatableQuerySet
from random import choice

def _set_random_avatar():
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
    return choice(choices)

class TranslatableUserQuerySet(TranslatableQuerySet):
    """Custom QuerySet that inherits from TranslatableQuerySet."""
    pass

class TranslatableUserManager(UserManager, TranslatableManager):
    """Custom manager combining UserManager and TranslatableManager."""
    def get_queryset(self):
        return TranslatableUserQuerySet(self.model, using=self._db)

class UserModel(AbstractUser, TranslatableModel):
    first_name = None
    last_name = None

    # Assign the custom manager
    objects = TranslatableUserManager()

    translations = TranslatedFields(
        name=models.CharField(
            max_length=100,
            blank=True,
            null=True,
            verbose_name=_("Name"),
            help_text=_("Enter your full name."),
        ),
        bio=models.CharField(
            max_length=500,
            blank=True,
            null=True,
            verbose_name=_("Bio"),
            help_text=_("Write a short bio about yourself."),
        ),
    )

    avatar = models.ImageField(
        upload_to='avatars/',
        blank=True,
        null=True,
        default=None,
        verbose_name=_("Avatar"),
        help_text=_("Select an avatar for your profile."),
    )

    def get_user_shown_name(self):
        if self.name:
            return self.name
        else:
            return self.username

    def save(self, *args, **kwargs):
        if not self.avatar:
            self.avatar = _set_random_avatar()
        super().save(*args, **kwargs)

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")

    def __str__(self):
        return self.username

    def __repr__(self):
        return self.username
