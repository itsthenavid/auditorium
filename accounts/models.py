from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser
from random import choice
import datetime
from django.utils import timezone

# Create your models here.

def _set_user_random_avatar():
    """
    Placeholder function to set a random avatar for the user.
    This can be implemented later to assign a random avatar from a predefined list.
    """
    # Logic to select a random avatar from a predefined list or directory
    avatars = [f"avatar_{i}.webp" for i in range(1, 21)]

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
    profiles = models.JSONField(
        default=dict,
        verbose_name=_("Name and Bio"),
        help_text=_("Name and bio for different languages, stored as JSON."),
    )
    is_verified = models.BooleanField(
        default=False,
        verbose_name=_("Is Verified"),
        help_text=_("Indicates whether the user has verified their account."),
    )
    
    def __str__(self):
        return self.username


class EmailVerificationCode(models.Model):
    """
    Model to store email verification codes for users.
    This is used to verify the user's email address during registration or changes.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='email_verification')
    code = models.CharField(max_length=64, verbose_name=_("Verification Code"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Created At"))
    expires_at = models.DateTimeField(verbose_name=_("Expires At"))
    is_for_token = models.BooleanField(default=True)  # True: توکن لینک، False: کد ۱۰ رقمی

    def is_expired(self):
        return timezone.now() > self.expires_at

    def save(self, *args, **kwargs):
        if not self.expires_at:
            duration = 15 if self.is_for_token else 5
            self.expires_at = timezone.now() + datetime.timedelta(minutes=duration)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Verification code for {self.user.username} - {self.code}"
