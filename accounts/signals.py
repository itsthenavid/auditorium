import logging
from django.dispatch import receiver
from django.db.models.signals import pre_save, post_save
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
import time
import traceback
from django.urls import reverse_lazy

from allauth.account.models import EmailAddress
from django_redis import get_redis_connection

from .models import User

# Create your signals here.

logger = logging.getLogger(__name__)
User = get_user_model()

@receiver(pre_save, sender=User)
def handle_email_change(sender, instance, **kwargs):
    try:
        if not hasattr(instance, '_request'):
            logger.warning("[handle_email_change] No request object available for user {}".format(instance.id))
            return
        request = instance._request
        logger.debug("[handle_email_change] Request object available: {}".format(bool(request)))
        old_instance = User.objects.get(id=instance.id)
        if instance.email != old_instance.email:
            logger.debug("[handle_email_change] Email change detected for user {}: old={}, new={}".format(
                instance.id, old_instance.email, instance.email))
            instance.is_verified = False
            conn = get_redis_connection('default')
            user_key = f"persistent_messages:{instance.id}"
            message_id = f"msg-email-verification-{instance.id}-{int(time.time())}"
            message_text = _(
                'Your email has been changed, so we’ve unverified it. '
                'Please verify your new email <a href="{}">here</a>.'
            ).format(reverse_lazy('accounts:verify_email'))
            message_data = f"{message_text}|persistent warning email-verification"
            try:
                conn.hset(user_key, message_id, message_data)
                logger.debug("[handle_email_change] Redis hset: user_key={}, message_id={}, data={}".format(
                    user_key, message_id, message_data))
            except Exception as e:
                logger.error("[handle_email_change] Failed to store message in Redis for user {}: {}".format(
                    instance.id, str(e)), exc_info=True)
            from django.contrib import messages
            messages.warning(request, message_text, extra_tags='persistent warning email-verification')
            logger.debug("[handle_email_change] Warning message added for user {}: {}".format(instance.id, message_text))
    except User.DoesNotExist:
        logger.warning("[handle_email_change] User {} does not exist".format(instance.id))
    except Exception as e:
        logger.error("[handle_email_change] Unexpected error for user {}: {}".format(instance.id, str(e)), exc_info=True)

@receiver(post_save, sender=EmailAddress)
def handle_email_verification(sender, instance, created, **kwargs):
    try:
        user = instance.user
        logger.debug("[handle_email_verification] Processing EmailAddress for user {}: verified={}, primary={}".format(
            user.id, instance.verified, instance.primary))
        if instance.verified and instance.primary:
            user.is_verified = True
            user.save()
            logger.debug("[handle_email_verification] User {} marked as verified".format(user.id))
            # Remove email-verification message from Redis
            conn = get_redis_connection('default')
            user_key = f"persistent_messages:{user.id}"
            for message_id in conn.hkeys(user_key):
                message_id = message_id.decode('utf-8')
                if 'email-verification' in conn.hget(user_key, message_id).decode('utf-8'):
                    conn.hdel(user_key, message_id)
                    logger.debug("[handle_email_verification] Removed email-verification message {} for user {}".format(
                        message_id, user.id))
    except Exception as e:
        logger.error("[handle_email_verification] Error for user {}: {}".format(instance.user.id, str(e)), exc_info=True)
