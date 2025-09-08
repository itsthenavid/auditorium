import logging
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser
from random import choice
import datetime
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.conf import settings
from django.core.mail import send_mail
import random
import string
from django.utils import timezone
from datetime import timedelta

# Create your models here.

logger = logging.getLogger(__name__)

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
    password_history = models.JSONField(default=list, verbose_name=_("Password History"), help_text=_("Stores the last 5 passwords used."))


    email = models.EmailField(
        _("Email Address"),
        # unique=True,
        help_text=_("Enter a valid email address. This will be used for account verification and notifications."),
        blank=True,
        null=True
    )

    EMAIL_FIELD = 'email'

    def add_password_to_history(self, password):
        """Add a new password hash to history, keeping only the last 5."""
        from django.contrib.auth.hashers import make_password
        hashed_password = make_password(password)
        history = self.password_history
        history.append(hashed_password)
        if len(history) > 5:
            history = history[-5:]
        self.password_history = history
        self.save()

    def is_password_reused(self, password):
        """Check if the password was previously used."""
        from django.contrib.auth.hashers import check_password
        return any(check_password(password, hashed) for hashed in self.password_history)

    def clean(self):
        for lang in self.profiles:
            if lang not in self.valid_languages:
                raise ValidationError(f"Invalid language code: {lang}")
        if self.email:
          if User.objects.exclude(pk=self.pk).filter(email__iexact=self.email).exists():
            raise ValidationError({"email": _("This email is already in use / already exists.")})
    
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


class AuditoCode(models.Model):
    TYPE_CHOICES = (
        ('login', 'Login'),
        ('password', 'Password Change'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=15, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='login')

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
            if not AuditoCode.objects.filter(code=code).exists():
                return code

    def is_valid(self):
        return not self.is_used and self.expires_at > timezone.now()

    def send_code_email(self):
        """Send the AuditoCode via email based on its type."""
        subject = _('Your Login Code') if self.type == 'login' else _('Your Password Change Verification Code')
        message = _(
            f'Hello {self.user.username},\n\n'
            f'Your {"login" if self.type == "login" else "password change"} code is: {self.code}\n\n'
            f'This code is valid for 10 minutes.\n\n'
            f'If you did not request this code, please ignore this email.'
        )
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[self.user.email],
                fail_silently=False,
            )
            logger.debug(f"[AuditoCode] Sent {self.type} code to {self.user.email}: {self.code}")
        except Exception as e:
            logger.error(f"[AuditoCode] Error sending {self.type} code to {self.user.email}: {str(e)}")
            raise

    def __str__(self):
        return f"{self.user.username} - {self.code} ({self.type})"
