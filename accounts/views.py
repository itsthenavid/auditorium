from django.urls import reverse_lazy
from django.views.generic import UpdateView, TemplateView, View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect
from django.utils.translation import gettext_lazy as _
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.utils.timezone import now
from django.conf import settings
import logging

from allauth.account.views import SignupView
from allauth.account.models import EmailAddress, EmailConfirmation, EmailConfirmationHMAC
from django_redis import get_redis_connection

from extensions.mixins import RateLimitMixin, RequireGetMixin
from extensions.utils import create_and_send_verification_code
from .forms import RegisterForm, ProfileImageForm, ProfileInfoForm, EmailVerificationForm
from .models import User, EmailVerificationCode

# Create your views here.

logger = logging.getLogger(__name__)
User = get_user_model()


class CustomSignupView(RateLimitMixin, SignupView):
    """Handle user signup with rate limiting and custom form."""
    form_class = RegisterForm
    template_name = 'account/signup.html'
    rate = '3/5m'
    key = 'user'
    rate_limit_methods = ['POST']

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['language'] = self.kwargs.get('lang_code', self.request.LANGUAGE_CODE)
        return kwargs

    def form_valid(self, form):
        logger.debug("Handling form_valid for CustomSignupView")
        response = super().form_valid(form)
        user = self.user
        conn = get_redis_connection('default')
        user_key = f"persistent_messages:{user.id}"
        
        if user.email:
            try:
                email_address, created = EmailAddress.objects.get_or_create(
                    user=user,
                    email=user.email,
                    defaults={'verified': False, 'primary': True}
                )
                if created:
                    logger.debug(f"Created new EmailAddress for user {user.id}: {user.email}")
                
                email_address.send_confirmation(self.request)
                expires_at = int((now().timestamp() + 15 * 60) * 1000)
                logger.debug(f"Link expires at: {expires_at}")
                
                message_id = f"msg-{user.id}-{int(now().timestamp())}"
                message_text = _('A verification link has been sent to your email (valid for 15 minutes, remaining: <span class="timer"></span>).')
                message_data = f"{message_text}|persistent success email-verification {expires_at}|{expires_at}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, 15 * 60)
                
                messages.success(self.request, message_text, extra_tags=f'persistent success email-verification {expires_at}')
            except Exception as e:
                logger.error(f"Error sending confirmation for user {user.id}: {str(e)}")
                message_id = f"msg-{user.id}-{int(now().timestamp())}"
                message_text = _('Failed to send confirmation email. Please go to the verification page to request a 10-digit code.')
                message_data = f"{message_text}|persistent error email-verification|{int(now().timestamp() + 15 * 60 * 1000)}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, 15 * 60)
                messages.error(self.request, message_text, extra_tags='persistent error email-verification')
                return redirect('accounts:verify_email')
        else:
            logger.debug(f"No email provided for user {user.id}, redirecting to verify_email")
            message_id = f"msg-{user.id}-{int(now().timestamp())}"
            message_text = _("No email provided. Please add an email in your profile to verify it.")
            message_data = f"{message_text}|persistent info email-verification|{int(now().timestamp() + 15 * 60 * 1000)}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 15 * 60)
            messages.info(self.request, message_text, extra_tags='persistent info email-verification')
            return redirect('accounts:verify_email')
        return redirect('pages:index')

    def form_invalid(self, form):
        logger.debug(f"Form errors in CustomSignupView: {form.errors}")
        for field, errors in form.errors.items():
            for error in errors:
                if field == 'username':
                    if 'required' in error.lower():
                        messages.error(self.request, _("Username is required. Please enter a username."), extra_tags='error')
                    elif 'unique' in error.lower():
                        messages.error(self.request, _("This username is already taken. Please choose a different one."), extra_tags='error')
                    else:
                        messages.error(self.request, _("Invalid username. It must be 3-30 characters and contain only letters, numbers, or underscores."), extra_tags='error')
                elif field == 'email':
                    if 'required' in error.lower():
                        messages.error(self.request, _("Email is required. Please enter an email address."), extra_tags='error')
                    elif 'invalid' in error.lower():
                        messages.error(self.request, _("Email format is invalid. Please enter a valid email like example@domain.com."), extra_tags='error')
                    elif 'unique' in error.lower():
                        messages.error(self.request, _("This email is already registered. Please use a different email or log in."), extra_tags='error')
                    else:
                        messages.error(self.request, _("Invalid email address. Please check and try again."), extra_tags='error')
                elif field == 'password1':
                    if 'required' in error.lower():
                        messages.error(self.request, _("Password is required. Please enter a password."), extra_tags='error')
                    else:
                        messages.error(self.request, _("Password is too weak. It must be at least 8 characters and include letters and numbers."), extra_tags='error')
                elif field == 'password2':
                    if 'required' in error.lower():
                        messages.error(self.request, _("Please confirm your password."), extra_tags='error')
                    elif 'password_mismatch' in error.lower():
                        messages.error(self.request, _("Passwords do not match. Please ensure both passwords are identical."), extra_tags='error')
                    else:
                        messages.error(self.request, _("Invalid password confirmation. Please check and try again."), extra_tags='error')
                else:
                    messages.error(self.request, _(f"Error in {field}: {error}"), extra_tags='error')
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error')
        return render(self.request, self.template_name, {'form': form})


class ProfileUpdateView(LoginRequiredMixin, UpdateView):
    """Allow logged-in users to update profile info or image."""
    model = User
    template_name = 'accounts/profile.html'
    success_url = reverse_lazy('accounts:profile_view')

    def get_form_class(self):
        form_type = self.request.POST.get('form_type')
        logger.debug(f"Form type received: {form_type}")
        return ProfileImageForm if form_type == 'image' else ProfileInfoForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        if self.get_form_class() == ProfileInfoForm:
            kwargs['language'] = self.request.LANGUAGE_CODE
        return kwargs

    def get_object(self):
        return self.request.user

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['image_form'] = ProfileImageForm(instance=self.request.user)
        context['info_form'] = ProfileInfoForm(
            instance=self.request.user,
            language=self.request.LANGUAGE_CODE
        )
        return context

    def form_valid(self, form):
        logger.debug(f"Form data: {self.request.POST}")
        logger.debug(f"Cleaned data: {form.cleaned_data}")
        form.instance.form_type = self.request.POST.get('form_type')
        user = self.request.user
        old_data = User.objects.get(id=user.id)
        conn = get_redis_connection('default')
        user_key = f"persistent_messages:{user.id}"

        if form.__class__ == ProfileInfoForm:
            if 'username' in form.cleaned_data and form.cleaned_data.get('username') != old_data.username:
                logger.debug(f"Username changed from '{old_data.username}' to '{form.cleaned_data.get('username')}'")
                messages.success(self.request, _(f"Your username has successfully changed to '{form.cleaned_data.get('username')}'"), extra_tags='success')
            if 'email' in form.cleaned_data and form.cleaned_data.get('email') != old_data.email:
                logger.debug(f"Email changed from '{old_data.email}' to '{form.cleaned_data.get('email')}'")
                messages.success(self.request, _(f"Your email has been successfully updated to '{form.cleaned_data.get('email')}'"), extra_tags='success')
                user.is_verified = False
                user.save()
                message_id = f"msg-{user.id}-{int(now().timestamp())}"
                message_text = _("Please verify your new email address.")
                message_data = f"{message_text}|persistent info email-verification|{int(now().timestamp() + 15 * 60 * 1000)}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, 15 * 60)
                messages.info(self.request, message_text, extra_tags='persistent info email-verification')
                return redirect('accounts:verify_email')
            language = self.request.LANGUAGE_CODE
            old_profile = old_data.profiles.get(language, {})
            if 'name' in form.cleaned_data and form.cleaned_data.get('name') != (old_profile.get('name') or ''):
                logger.debug(f"Name changed from '{old_profile.get('name') or ''}' to '{form.cleaned_data.get('name')}'")
                messages.success(self.request, _(f"Your name has been successfully updated to '{form.cleaned_data.get('name')}'"), extra_tags='success')
            if 'bio' in form.cleaned_data and form.cleaned_data.get('bio') != (old_profile.get('bio') or ''):
                logger.debug(f"Bio changed from '{old_profile.get('bio') or ''}' to '{form.cleaned_data.get('bio')}'")
                messages.success(self.request, _("Your bio has been successfully updated."), extra_tags='success')
        elif form.__class__ == ProfileImageForm:
            if 'avatar' in form.cleaned_data and form.cleaned_data.get('avatar'):
                if not old_data.avatar or form.cleaned_data.get('avatar') != old_data.avatar:
                    logger.debug(f"Avatar changed from '{old_data.avatar}' to '{form.cleaned_data.get('avatar')}'")
                    messages.success(self.request, _("Your avatar has been changed"), extra_tags='success')
            if 'banner' in form.cleaned_data and form.cleaned_data.get('banner'):
                if not old_data.banner or form.cleaned_data.get('banner') != old_data.banner:
                    logger.debug(f"Banner changed from '{old_data.banner}' to '{form.cleaned_data.get('banner')}'")
                    messages.success(self.request, _("Your banner has been changed"), extra_tags='success')

        return super().form_valid(form)

    def form_invalid(self, form):
        logger.debug(f"Form errors in ProfileUpdateView: {form.errors}")
        form_type = self.request.POST.get('form_type')
        if form_type == 'image':
            for field, errors in form.errors.items():
                for error in errors:
                    if field == 'avatar':
                        messages.error(self.request, _("Invalid avatar image. Please upload a valid image (e.g., JPG, PNG)."), extra_tags='error')
                    elif field == 'banner':
                        messages.error(self.request, _("Invalid banner image. Please upload a valid image (e.g., JPG, PNG)."), extra_tags='error')
                    else:
                        messages.error(self.request, _(f"Error in {field}: {error}"), extra_tags='error')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    if field == 'username':
                        if 'required' in error.lower():
                            messages.error(self.request, _("Username is required. Please enter a username."), extra_tags='error')
                        elif 'unique' in error.lower():
                            messages.error(self.request, _("This username is already taken. Please choose a different one."), extra_tags='error')
                        else:
                            messages.error(self.request, _("Invalid username. It must be 3-30 characters and contain only letters, numbers, or underscores."), extra_tags='error')
                    elif field == 'email':
                        if 'invalid' in error.lower():
                            messages.error(self.request, _("Email format is invalid. Please enter a valid email like example@domain.com."), extra_tags='error')
                        elif 'unique' in error.lower():
                            messages.error(self.request, _("This email is already registered. Please use a different email."), extra_tags='error')
                        else:
                            messages.error(self.request, _("Invalid email address. Please check and try again."), extra_tags='error')
                    elif field == 'name':
                        messages.error(self.request, _("Invalid name. Please use valid characters."), extra_tags='error')
                    elif field == 'bio':
                        messages.error(self.request, _("Invalid bio. Please use valid characters and keep it under 500 characters."), extra_tags='error')
                    else:
                        messages.error(self.request, _(f"Error in {field}: {error}"), extra_tags='error')
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error')
        return super().form_invalid(form)


class ProfileView(LoginRequiredMixin, TemplateView):
    """Display user profile based on selected language."""
    template_name = 'accounts/profile_view.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        language = self.request.LANGUAGE_CODE
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if language not in valid_languages:
            language = 'en'
        context['avatar'] = user.avatar.url if user.avatar else f"{settings.STATIC_URL}shared/avatars/avatar_1.webp"
        context['banner'] = user.banner.url if user.banner else f"{settings.STATIC_URL}shared/banners/default_banner.webp"
        context['username'] = user.username
        context['email'] = user.email
        context['name'] = user.profiles.get(language, {}).get('name', user.username)
        context['bio'] = user.profiles.get(language, {}).get('bio', '')
        context['language'] = language
        return context


class EmailVerifyLinkView(RequireGetMixin, View):
    """Verify email via link."""
    def get(self, request, key):
        logger.debug(f"Handling EmailVerifyLinkView with key: {key}")
        confirmation = EmailConfirmationHMAC.from_key(key)
        if not confirmation:
            try:
                confirmation = EmailConfirmation.objects.get(key=key.lower())
            except EmailConfirmation.DoesNotExist:
                confirmation = None

        conn = get_redis_connection('default')
        user_key = f"persistent_messages:{request.user.id if request.user.is_authenticated else 'anonymous'}"

        if confirmation:
            time_diff = (now() - confirmation.sent).total_seconds()
            if time_diff > 15 * 60:
                message_id = f"msg-{request.user.id}-{int(now().timestamp())}"
                message_text = _("The verification link has expired. Please request a 10-digit code.")
                message_data = f"{message_text}|persistent error email-verification|{int(now().timestamp() + 15 * 60 * 1000)}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, 15 * 60)
                messages.error(self.request, message_text, extra_tags='persistent error email-verification')
                return redirect('accounts:verify_email')

            confirmation.confirm(request)
            messages.success(request, _("Your email has been verified successfully."), extra_tags='success')
            return redirect('accounts:profile_view')

        message_id = f"msg-{request.user.id}-{int(now().timestamp())}"
        message_text = _("The verification link is invalid. Please request a 10-digit code.")
        message_data = f"{message_text}|persistent error email-verification|{int(now().timestamp() + 15 * 60 * 1000)}"
        conn.hset(user_key, message_id, message_data)
        conn.expire(user_key, 15 * 60)
        messages.error(self.request, message_text, extra_tags='persistent error email-verification')
        return redirect('accounts:verify_email')


class VerifyEmailView(RateLimitMixin, LoginRequiredMixin, View):
    """Verify email with a 10-digit code."""
    template_name = 'accounts/verify-email.html'
    rate = '3/5m'
    key = 'user'
    rate_limit_methods = ['GET', 'POST']

    def get(self, request):
        logger.debug("Handling GET for VerifyEmailView")
        conn = get_redis_connection('default')
        user_key = f"persistent_messages:{request.user.id}"
        try:
            count = conn.get(f"ratelimit:{self.key}:{request.user.id}")
            count = int(count) if count else 0
            logger.debug(f"Current request count for ratelimit:{self.key}:{request.user.id} (GET): {count}")
            limit = int(self.rate.split('/')[0])
            if count < limit:
                expires_at = create_and_send_verification_code(request.user, is_for_token=False)
                message_id = f"msg-{request.user.id}-{int(now().timestamp())}"
                message_text = _('A 10-digit verification code has been sent to your email (valid for 5 minutes, remaining: <span class="timer"></span>).')
                message_data = f"{message_text}|persistent info code-verification {expires_at}|{expires_at}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, 5 * 60)
                messages.info(self.request, message_text, extra_tags=f'persistent info code-verification {expires_at}')
            else:
                logger.debug(f"Skipping code send due to rate limit for {user_key}")
                messages.warning(self.request, _("You have exceeded the request limit. Please try again later."), extra_tags='warning')
        except Exception as e:
            logger.error(f"Error in create_and_send_verification_code: {str(e)}")
            message_id = f"msg-{request.user.id}-{int(now().timestamp())}"
            message_text = _('An error occurred while sending the verification code. Please try again.')
            message_data = f"{message_text}|persistent error code-verification|{int(now().timestamp() + 5 * 60 * 1000)}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 5 * 60)
            messages.error(self.request, message_text, extra_tags='persistent error code-verification')
        return render(request, self.template_name, {'form': EmailVerificationForm()})

    def post(self, request, *args, **kwargs):
        logger.debug("Handling POST for VerifyEmailView")
        full_code = ''.join([request.POST.get(f'code_{i}', '') for i in range(10)])
        form = EmailVerificationForm({'code': full_code})
        conn = get_redis_connection('default')
        user_key = f"persistent_messages:{request.user.id}"

        if form.is_valid():
            input_code = form.cleaned_data['code']
            try:
                evc = request.user.email_verification
                if evc.is_for_token:
                    message_id = f"msg-{request.user.id}-{int(now().timestamp())}"
                    message_text = _("This code is for token verification. Please request a 10-digit code.")
                    message_data = f"{message_text}|persistent error code-verification|{int(now().timestamp() + 5 * 60 * 1000)}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, 5 * 60)
                    messages.error(self.request, message_text, extra_tags='persistent error code-verification')
                    return render(request, self.template_name, {'form': form})

                if evc.is_expired():
                    message_id = f"msg-{request.user.id}-{int(now().timestamp())}"
                    message_text = _("The verification code has expired. Please request a new one.")
                    message_data = f"{message_text}|persistent error code-verification|{int(now().timestamp() + 5 * 60 * 1000)}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, 5 * 60)
                    messages.error(self.request, message_text, extra_tags='persistent error code-verification')
                    return render(request, self.template_name, {'form': None})

                if evc.code == input_code:
                    request.user.is_verified = True
                    request.user.save()
                    evc.delete()
                    messages.success(request, _("Your email has been verified successfully."), extra_tags='success')
                    return redirect('accounts:profile_view')
                else:
                    message_id = f"msg-{request.user.id}-{int(now().timestamp())}"
                    message_text = _("The verification code you entered is incorrect. Please try again.")
                    message_data = f"{message_text}|persistent error code-verification|{int(now().timestamp() + 5 * 60 * 1000)}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, 5 * 60)
                    messages.error(self.request, message_text, extra_tags='persistent error code-verification')
            except EmailVerificationCode.DoesNotExist:
                message_id = f"msg-{request.user.id}-{int(now().timestamp())}"
                message_text = _("No verification code found. Please request a new one.")
                message_data = f"{message_text}|persistent error code-verification|{int(now().timestamp() + 5 * 60 * 1000)}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, 5 * 60)
                messages.error(self.request, message_text, extra_tags='persistent error code-verification')
        else:
            message_id = f"msg-{request.user.id}-{int(now().timestamp())}"
            message_text = _("The entered code is invalid. Please ensure all 10 digits are correct.")
            message_data = f"{message_text}|persistent error code-verification|{int(now().timestamp() + 5 * 60 * 1000)}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 5 * 60)
            messages.error(self.request, message_text, extra_tags='persistent error code-verification')
        return render(request, self.template_name, {'form': form})
