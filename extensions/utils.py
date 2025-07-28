from django.utils import timezone
import random
from accounts.models import EmailVerificationCode
from django.core.mail import send_mail
from django.conf import settings
import logging

# Create the helper functions here.

logger = logging.getLogger(__name__)

def create_and_send_verification_code(user, is_for_token=False):
    try:
        # Generate a random 10-digit code
        code = ''.join(random.choices('0123456789', k=10))
        expires_at = timezone.now() + timezone.timedelta(minutes=5 if not is_for_token else 15)
        
        # Delete any existing verification code for the user
        EmailVerificationCode.objects.filter(user=user).delete()
        
        # Create EmailVerificationCode instance
        evc = EmailVerificationCode(
            user=user,
            code=code,
            expires_at=expires_at,
            is_for_token=is_for_token
        )
        evc.save()
        logger.debug(f"Created EmailVerificationCode for user {user.id}: code={code}, expires_at={expires_at}")
        
        # Send email
        subject = 'Verify Your Email'
        message = f'Your verification code is: {code}\nThis code is valid for {5 if not is_for_token else 15} minutes.'
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False
        )
        logger.debug(f"Sent verification email to {user.email} with code {code}")
        
        return int(expires_at.timestamp() * 1000)
    except Exception as e:
        logger.error(f"Error in create_and_send_verification_code: {str(e)}")
        raise
