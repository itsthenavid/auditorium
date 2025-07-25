from django.utils import timezone
from datetime import timedelta
from django.utils.timezone import datetime
from django.contrib.auth import get_user_model
import random
from django.core.mail import send_mail
import random
import string
from django.utils import timezone

from accounts.models import EmailVerificationCode
from accounts.forms import EmailVerificationForm

# Create the helpers functions here.

User = get_user_model()

def generate_code(length=10):
    return ''.join(random.choices('0123456789', k=length))

def send_verification_email(user, code):
    subject = 'کد تایید ایمیل شما - آودیتوریوم'
    message = f'سلام {user.username} عزیز،\n\nکد تایید ایمیل شما: {code}\nلطفاً این کد را در سایت وارد کنید تا ایمیل شما تأیید شود.\n\nبا احترام، تیم آودیتوریوم'
    from_email = 'no-reply@auditorium.com'
    recipient_list = [user.email]
    send_mail(subject, message, from_email, recipient_list)

def create_and_send_verification_code(user, is_for_token=True):
    EmailVerificationCode.objects.filter(user=user).delete()

    if is_for_token:
        code = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
    else:
        code = ''.join(random.choices(string.digits, k=10))

    evc = EmailVerificationCode.objects.create(
        user=user,
        code=code,
        is_for_token=is_for_token,
        expires_at=timezone.now() + timedelta(seconds=15 if is_for_token else 15)
    )

    if is_for_token:
        verification_link = f"http://localhost/accounts/verify-email/{user.pk}/{code}/"
        print(f"Send email with verification link: {verification_link}")
    else:
        print(f"Send email with verification code: {code}")
