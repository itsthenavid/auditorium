from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser
from random import choice
import datetime
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.conf import settings
import random
import string
from django.utils import timezone
from datetime import timedelta

# Create your models here.

def _set_user_random_avatar():
    avatars = [f"avatar_{i}.webp" for i in range(1, 21)]
    return choice(avatars)

def get_default_profiles():
    return {lang: {'name': '', 'bio': ''} for lang in ['en', 'fa', 'ckb', 'ku']}


class User(AbstractUser):
    valid_languages = ('en', 'fa', 'ckb', 'ku', )

    avatar = models.ImageField(
        default=_set_user_random_avatar,
        verbose_name=_("Avatar"),
        upload_to="avatars/",
        help_text=_("Upload a profile picture for the user.")
    )
    banner = models.ImageField(
        default=f"{settings.STATIC_URL}shared/banners/default_banner.webp",
        verbose_name=_("Banner"),
        upload_to="banners/",
        help_text=_("Upload a banner image for the user profile.")
    )
    profiles = models.JSONField(
        default=get_default_profiles,
        verbose_name=_("Name and Bio"),
        help_text=_("Name and bio for different languages, stored as JSON.")
    )
    is_verified = models.BooleanField(
        default=False,
        verbose_name=_("Is Verified"),
        help_text=_("Indicates whether the user has verified their account.")
    )

    def clean(self):
        for lang in self.profiles:
            if lang not in self.valid_languages:
                raise ValidationError(f"Invalid language code: {lang}")
    
    def clean_bio(self):
        for lang, profile in self.profiles.items():
            bio = profile.get('bio', '')
            if bio and len(bio) > 500:
                raise ValidationError(_(f"Bio for language {lang} cannot exceed 500 characters."))
    
    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username


class EmailVerificationCode(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='email_verification')
    code = models.CharField(max_length=64, verbose_name=_("Verification Code"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Created At"))
    expires_at = models.DateTimeField(verbose_name=_("Expires At"))
    is_for_token = models.BooleanField(default=True, help_text=_("True for link-based, False for 10-digit code"))
    attempt_count = models.PositiveIntegerField(default=0, verbose_name=_("Failed Attempt Count"))
    lockout_until = models.DateTimeField(null=True, blank=True, verbose_name=_("Lockout Until"))

    def is_expired(self):
        return timezone.now() > self.expires_at

    def is_locked_out(self):
        return self.lockout_until and timezone.now() < self.lockout_until

    def increment_attempts(self):
        self.attempt_count += 1
        if self.attempt_count >= 3:
            self.lockout_until = timezone.now() + datetime.timedelta(minutes=5)
        self.save()

    def reset_attempts(self):
        self.attempt_count = 0
        self.lockout_until = None
        self.save()

    def save(self, *args, **kwargs):
        if not self.expires_at:
            duration = 15 if self.is_for_token else 5
            self.expires_at = timezone.now() + datetime.timedelta(minutes=duration)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Verification code for {self.user.username} - {self.code}"


class LoginCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=15, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    
    def save(self, *args, **kwargs):
        if not self.code:
            self.code = self.generate_code()
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)
    
    @staticmethod
    def generate_code():

        characters = string.ascii_uppercase + string.digits
        while True:
            code = ''.join(random.choice(characters) for _ in range(15))
            if not LoginCode.objects.filter(code=code).exists():
                return code
    
    def is_valid(self):

        return not self.is_used and self.expires_at > timezone.now()
    
    def __str__(self):
        return f"{self.user.username} - {self.code}"
