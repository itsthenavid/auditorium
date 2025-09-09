from django.db.models.signals import post_save
from django.dispatch import receiver

from accounts.models import User
from managements.models import Settings

# Signal to create a Settings instance whenever a new User is created

@receiver(post_save, sender=User)
def create_user_settings(sender, instance, created, **kwargs):
    if created:
        Settings.objects.create(user=instance)
