from django.utils import timezone
import random
from django.core.mail import send_mail
from django.conf import settings
import logging
import traceback

from accounts.models import EmailVerificationCode

logger = logging.getLogger(__name__)

# Create your helper tools here.

def create_and_send_verification_code(user, is_for_token=False):
    try:
        # Check for existing code and lockout
        existing_code = EmailVerificationCode.objects.filter(user=user, is_for_token=is_for_token).first()
        if existing_code and existing_code.is_locked_out():
            logger.debug(f"User {user.id} is locked out until {existing_code.lockout_until}")
            raise ValueError("User is temporarily locked out due to too many failed attempts.")

        code = ''.join(random.choices('0123456789', k=10))
        expires_at = timezone.now() + timezone.timedelta(minutes=5 if not is_for_token else 15)
        
        # Delete existing code and reset attempts
        EmailVerificationCode.objects.filter(user=user).delete()
        
        evc = EmailVerificationCode(
            user=user,
            code=code,
            expires_at=expires_at,
            is_for_token=is_for_token
        )
        evc.save()
        logger.debug(f"Created EmailVerificationCode for user {user.id}: code={code}, expires_at={expires_at}")
        
        subject = 'Verify Your Email'
        message = f'Your verification code is: {code}\nThis code is valid for {5 if not is_for_token else 15} minutes.'
        logger.debug(f"Preparing to send email to {user.email} with subject: {subject}")
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False
        )
        logger.info(f"Sent verification email to {user.email} with code {code}")
        
        return int(expires_at.timestamp() * 1000)
    except Exception as e:
        logger.error(f"Error in create_and_send_verification_code for user {user.id}: {str(e)}\n{traceback.format_exc()}")
        raise
