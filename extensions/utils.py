import logging
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import get_user_model
import uuid
from django.core.mail import send_mail
from accounts.models import EmailVerificationCode
import random

# Create the helper functions here.

logger = logging.getLogger(__name__)
User = get_user_model()

def generate_code(length=10):
    return ''.join(random.choices('0123456789', k=length))

def send_verification_email(user, code, is_for_token=True):
    subject = 'کد یا لینک تأیید ایمیل - آودیتوریوم'
    if is_for_token:
        verification_link = f"http://localhost/accounts/verify-email/{user.pk}/{code}/"
        message = f'سلام {user.username} عزیز،\n\nبرای تأیید ایمیل خود، روی لینک زیر کلیک کنید:\n{verification_link}\nلینک تا ۱۵ دقیقه معتبر است.\n\nیا می‌توانید از کد ۱۰ رقمی که از طریق ایمیل دریافت می‌کنید استفاده کنید.\n\nبا احترام، تیم آودیتوریوم'
    else:
        message = f'سلام {user.username} عزیز،\n\nکد تأیید ایمیل شما: {code}\nلطفاً این کد را در سایت وارد کنید تا ایمیل شما تأیید شود. کد تا ۵ دقیقه معتبر است.\n\nبا احترام، تیم آودیتوریوم'
    from_email = 'no-reply@auditorium.com'
    recipient_list = [user.email]
    try:
        send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        logger.debug(f"Verification email sent to {user.email} with code: {code}")
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {str(e)}")
        raise

def create_and_send_verification_code(user, is_for_token=True):
    EmailVerificationCode.objects.filter(user=user).delete()

    if is_for_token:
        code = str(uuid.uuid4())
        expires_at = timezone.now() + timedelta(minutes=15)
    else:
        code = generate_code(10)
        expires_at = timezone.now() + timedelta(minutes=5)

    evc = EmailVerificationCode.objects.create(
        user=user,
        code=code,
        is_for_token=is_for_token,
        email=user.email
    )

    send_verification_email(user, code, is_for_token)
    expires_at_ms = expires_at.timestamp() * 1000
    logger.debug(f"Generated verification code for user {user.id}, code: {code}, expires_at: {expires_at_ms}")
    return expires_at_ms
