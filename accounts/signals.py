import logging
import time
from django.dispatch import receiver
from django.db.models.signals import pre_save, post_save
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.urls import reverse_lazy
from django.contrib.auth.signals import user_logged_in
from django.utils import translation

from django_redis import get_redis_connection
from allauth.account.models import EmailAddress

from .models import User

# Create your signals here.

logger = logging.getLogger(__name__)
User = get_user_model()


@receiver(pre_save, sender=User)
def handle_email_change(sender, instance, **kwargs):
    try:
        if not hasattr(instance, '_request'):
            logger.warning(f"[handle_email_change] No request object for user {getattr(instance, 'id', 'new')}")
            return
        request = instance._request

        if instance.id is None:
            return  # New user, ignore

        old_instance = User.objects.get(id=instance.id)
        if instance.email != old_instance.email:
            logger.debug(f"[handle_email_change] Email changed for user {instance.id}: {old_instance.email} -> {instance.email}")
            instance.is_verified = False


            if instance.email:
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
                    logger.debug(f"[handle_email_change] Redis hset: {user_key}, {message_id}")
                except Exception as e:
                    logger.error(f"[handle_email_change] Redis error for user {instance.id}: {str(e)}", exc_info=True)
                from django.contrib import messages
                messages.warning(request, message_text, extra_tags='persistent warning email-verification')
                logger.debug(f"[handle_email_change] Warning message added for user {instance.id}")
    except User.DoesNotExist:
        logger.warning(f"[handle_email_change] User {getattr(instance, 'id', 'new')} does not exist")
    except Exception as e:
        logger.error(f"[handle_email_change] Unexpected error for user {getattr(instance, 'id', 'new')}: {str(e)}", exc_info=True)


@receiver(post_save, sender=EmailAddress)
def handle_email_verification(sender, instance, created, **kwargs):
    try:
        user = instance.user
        logger.debug(f"[handle_email_verification] EmailAddress for user {user.id}: verified={instance.verified}, primary={instance.primary}")

        if instance.verified and instance.primary:
            user.is_verified = True
            user.save()
            logger.debug(f"[handle_email_verification] User {user.id} marked as verified")


            conn = get_redis_connection('default')
            user_key = f"persistent_messages:{user.id}"
            for message_id in conn.hkeys(user_key):
                message_id_str = message_id.decode('utf-8')
                msg_content = conn.hget(user_key, message_id).decode('utf-8')
                if 'email-verification' in msg_content:
                    conn.hdel(user_key, message_id)
                    logger.debug(f"[handle_email_verification] Removed email-verification message {message_id_str} for user {user.id}")

    except Exception as e:
        logger.error(f"[handle_email_verification] Error for user {getattr(instance.user, 'id', 'unknown')}: {str(e)}", exc_info=True)

@receiver(user_logged_in)
def set_user_language(sender, request, user, **kwargs):
    try:
        user_lang = user.settings.language
        translation.activate(user_lang)
        request.session['django_language'] = user_lang
    except AttributeError:
        pass
