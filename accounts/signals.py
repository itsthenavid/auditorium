from allauth.account.signals import email_confirmed
from django.dispatch import receiver
from django.conf import settings
from django.contrib.auth import get_user_model

# Create signals for the apps.

User = get_user_model()

@receiver(email_confirmed)
def email_confirmed_(request, email_address, **kwargs):
    user = email_address.user
    if not user.is_verified:
        user.is_verified = True
        user.save()
