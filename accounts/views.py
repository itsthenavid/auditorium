import time
from django.http import HttpResponseRedirect
from django.urls import reverse_lazy
from django.views.generic import UpdateView, TemplateView, View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect
from django.utils.translation import gettext_lazy as _
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.utils.timezone import now
from django.conf import settings
import logging
import traceback

from django_redis import get_redis_connection
from allauth.account.views import SignupView, LoginView
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC, EmailAddress
from allauth.account.utils import send_email_confirmation

from extensions.mixins import RateLimitMixin, RequireGetMixin
from extensions.utils import create_and_send_verification_code
from .forms import RegisterForm, ProfileImageForm, ProfileInfoForm, EmailVerificationForm
from .models import User, EmailVerificationCode

# Create your views here.

logger = logging.getLogger(__name__)
User = get_user_model()

class RegisterView(SignupView):
    template_name = 'account/signup.html'
    form_class = RegisterForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['language'] = self.request.LANGUAGE_CODE or 'en'
        return kwargs

    def form_valid(self, form):
        try:
            logger.debug(f"[RegisterView] Processing signup for email: {form.cleaned_data['email']}")
            user = form.save(self.request)
            if user:
                logger.debug(f"[RegisterView] User created: {user.username}, ID: {user.id}")
                login(self.request, user, backend='django.contrib.auth.backends.ModelBackend')
                logger.debug(f"[RegisterView] User {user.username} logged in successfully")
                try:
                    email_confirmation = send_email_confirmation(self.request, user, signup=True)
                    expires_at = None
                    if isinstance(email_confirmation, EmailConfirmationHMAC):
                        expires_at = int(email_confirmation.expires_at.timestamp() * 1000)
                        logger.debug(f"[RegisterView] Email confirmation sent for user {user.id}, expires at {expires_at}")
                    else:
                        logger.warning(f"[RegisterView] email_confirmation is not an EmailConfirmation object: {email_confirmation}")
                        confirmation_timeout = getattr(settings, 'ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS', 15 / (24 * 60)) * 24 * 60 * 60
                        expires_at = int((time.time() + confirmation_timeout) * 1000)
                        logger.debug(f"[RegisterView] Fallback expires_at calculated for user {user.id}: {expires_at}")
                    conn = get_redis_connection('default')
                    user_key = f"persistent_messages:{user.id}"
                    self._clear_old_messages(conn, user_key)
                    message_id = f"msg-email-verification-{user.id}-{int(time.time())}"
                    message_text = _(
                        'A verification email with a link has been sent to your email '
                        '(valid for 15 minutes, remaining: <span class="timer"></span>). '
                        'Click the link to verify your email.'
                    )
                    message_data = f"{message_text}|persistent info email-verification|{expires_at}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, 15 * 60)
                    messages.info(self.request, message_text, extra_tags='persistent info email-verification')
                except Exception as e:
                    logger.error(f"[RegisterView] Error sending email confirmation for user {user.id}: {str(e)}")
                    messages.error(self.request, _("Error sending verification email. Please try again or request a new code."), extra_tags='error')
                return HttpResponseRedirect(reverse_lazy('accounts:profile_view'))
            else:
                logger.error("[RegisterView] User creation failed: form.save returned None")
                messages.error(self.request, _("Failed to create account. Please try again."), extra_tags='error')
                return self.form_invalid(form)
        except Exception as e:
            logger.error(f"[RegisterView] Unexpected error during signup: {str(e)}")
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error')
            return self.form_invalid(form)

    def _clear_old_messages(self, conn, user_key, exclude_tags=None):
        try:
            existing_messages = conn.hgetall(user_key)
            for msg_id, msg_data in existing_messages.items():
                try:
                    parts = msg_data.decode('utf-8').split('|')
                    if len(parts) != 3:
                        logger.error(f"[RegisterView] Invalid message format in {user_key} for msg_id {msg_id}: {msg_data}")
                        conn.hdel(user_key, msg_id)
                        continue
                    tags = parts[1]
                    expires_at = float(parts[2])
                    if expires_at < time.time() * 1000:
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[RegisterView] Deleted expired message {msg_id} from {user_key}")
                        continue
                    if exclude_tags and any(tag in tags for tag in exclude_tags):
                        continue
                    conn.hdel(user_key, msg_id)
                    logger.debug(f"[RegisterView] Deleted message {msg_id} from {user_key}")
                except (ValueError, IndexError) as e:
                    logger.error(f"[RegisterView] Invalid message format in {user_key} for msg_id {msg_id}: {str(e)}")
                    conn.hdel(user_key, msg_id)
        except Exception as e:
            logger.error(f"[RegisterView] Error clearing old messages from {user_key}: {str(e)}")
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error')

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            logger.debug(f"[RegisterView] User {request.user.id} is already authenticated, redirecting to profile")
            return HttpResponseRedirect(reverse_lazy('accounts:profile_view'))
        return super().get(request, *args, **kwargs)


class CustomLoginView(LoginView):
    def form_invalid(self, form):
        print("Form errors:", form.errors)
        self.request._messages._queued_messages.clear()
        if '__all__' in form.errors:
            for error in form.errors['__all__']:
                messages.error(self.request, error)
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(self.request, error)
        return super().form_invalid(form)

    def form_valid(self, form):
        return super().form_valid(form)


class ProfileUpdateView(LoginRequiredMixin, UpdateView):
    model = User
    template_name = 'accounts/profile.html'
    success_url = reverse_lazy('accounts:profile_view')

    def get_form_class(self):
        form_type = self.request.POST.get('form_type')
        logger.debug(f"[ProfileUpdateView] Form type received: {form_type}")
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
        logger.debug(f"[ProfileUpdateView] Form data: {self.request.POST}")
        logger.debug(f"[ProfileUpdateView] Cleaned data: {form.cleaned_data}")
        form.instance.form_type = self.request.POST.get('form_type')
        user = self.request.user
        old_data = User.objects.get(id=user.id)
        conn = get_redis_connection('default')
        user_key = f"persistent_messages:{user.id}"
        try:
            if form.__class__ == ProfileInfoForm:
                if 'username' in form.cleaned_data and form.cleaned_data.get('username') != old_data.username:
                    logger.debug(f"[ProfileUpdateView] Username changed from '{old_data.username}' to '{form.cleaned_data.get('username')}'")
                    user.username = form.cleaned_data['username']
                    messages.success(self.request, _(f"Your username has successfully changed to '{form.cleaned_data.get('username')}'"), extra_tags='success')
                
                language = self.request.LANGUAGE_CODE
                valid_languages = ['en', 'fa', 'ckb', 'ku']
                if language not in valid_languages:
                    language = 'en'
                old_profile = old_data.profiles.get(language, {})
                profiles = user.profiles or {}
                
                if 'name' in form.cleaned_data and form.cleaned_data.get('name') != (old_profile.get('name') or ''):
                    logger.debug(f"[ProfileUpdateView] Name changed from '{old_profile.get('name') or ''}' to '{form.cleaned_data.get('name')}'")
                    profiles[language] = profiles.get(language, {})
                    profiles[language]['name'] = form.cleaned_data['name']
                    messages.success(self.request, _(f"Your name has been successfully updated to '{form.cleaned_data.get('name')}'"), extra_tags='success')
                
                if 'bio' in form.cleaned_data and form.cleaned_data.get('bio') != (old_profile.get('bio') or ''):
                    logger.debug(f"[ProfileUpdateView] Bio changed from '{old_profile.get('bio') or ''}' to '{form.cleaned_data.get('bio')}'")
                    profiles[language] = profiles.get(language, {})
                    profiles[language]['bio'] = form.cleaned_data['bio']
                    messages.success(self.request, _("Your bio has been successfully updated."), extra_tags='success')
                
                user.profiles = profiles
                user.save()
                
                email_changed = 'email' in form.cleaned_data and form.cleaned_data.get('email') and form.cleaned_data.get('email') != old_data.email
                if email_changed:
                    logger.debug(f"[ProfileUpdateView] Email changed from '{old_data.email}' to '{form.cleaned_data.get('email')}'")
                    user.email = form.cleaned_data['email']
                    user.is_verified = False
                    user.save()
                    email_address, created = EmailAddress.objects.get_or_create(
                        user=user, email=form.cleaned_data.get('email'), defaults={'verified': False, 'primary': True}
                    )
                    email_address.send_confirmation(self.request)
                    expires_at = int((now().timestamp() + 15 * 60) * 1000)
                    message_id = f"msg-email-verification-{user.id}-{int(now().timestamp())}"
                    message_text = _('A verification link has been sent to your new email (valid for 15 minutes, remaining: <span class="timer"></span>).')
                    message_data = f"{message_text}|persistent success email-verification|{expires_at}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, 15 * 60)
                    messages.success(self.request, message_text, extra_tags=f'persistent success email-verification')
                    return redirect('accounts:verify_email')
                
                return super().form_valid(form)
            
            elif form.__class__ == ProfileImageForm:
                if 'avatar' in form.cleaned_data and form.cleaned_data.get('avatar'):
                    if not old_data.avatar or form.cleaned_data.get('avatar') != old_data.avatar:
                        logger.debug(f"[ProfileUpdateView] Avatar changed from '{old_data.avatar}' to '{form.cleaned_data.get('avatar')}'")
                        messages.success(self.request, _("Your avatar has been changed"), extra_tags='success')
                if 'banner' in form.cleaned_data and form.cleaned_data.get('banner'):
                    if not old_data.banner or form.cleaned_data.get('banner') != old_data.banner:
                        logger.debug(f"[ProfileUpdateView] Banner changed from '{old_data.banner}' to '{form.cleaned_data.get('banner')}'")
                        messages.success(self.request, _("Your banner has been changed"), extra_tags='success')
            
            return super().form_valid(form)
        
        except Exception as e:
            logger.error(f"[ProfileUpdateView] Error in form_valid for user {user.id}: {str(e)}\n{traceback.format_exc()}")
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error')
            return self.form_invalid(form)

    def form_invalid(self, form):
        logger.debug(f"[ProfileUpdateView] Form errors: {form.errors}")
        form_type = self.request.POST.get('form_type')
        try:
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
            messages.error(self.request, _("Please correct the errors below and try again."), extra_tags='error')
        except Exception as e:
            logger.error(f"[ProfileUpdateView] Error in form_invalid: {str(e)}\n{traceback.format_exc()}")
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error')
        return super().form_invalid(form)


class ProfileView(LoginRequiredMixin, TemplateView):
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
    def get(self, request, key):
        logger.debug(f"[EmailVerifyLinkView] Handling with key: {key}")
        try:
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
                    self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt'])
                    message_id = f"msg-link-expired-{request.user.id}-{int(now().timestamp())}"
                    message_text = _('The verification link has expired. Please request a 10-digit code <a href="%s">here</a>.') % reverse_lazy('accounts:verify_email')
                    message_data = f"{message_text}|persistent error email-verification|{int(now().timestamp() + 15 * 60 * 1000)}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, 15 * 60)
                    messages.error(self.request, message_text, extra_tags=f'persistent error email-verification')
                    return redirect('accounts:verify_email')
                confirmation.confirm(self.request)
                self._clear_old_messages(conn, user_key)
                messages.success(self.request, _("Your email has been verified successfully. You're awesome!"), extra_tags='success')
                return redirect('accounts:profile_view')
            self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt'])
            message_id = f"msg-invalid-link-{request.user.id}-{int(now().timestamp())}"
            message_text = _('The verification link is invalid. Please request a 10-digit code <a href="%s">here</a>.') % reverse_lazy('accounts:verify_email')
            message_data = f"{message_text}|persistent error email-verification|{int(now().timestamp() + 15 * 60 * 1000)}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 15 * 60)
            messages.error(self.request, message_text, extra_tags=f'persistent error email-verification')
            return redirect('accounts:verify_email')
        except Exception as e:
            logger.error(f"[EmailVerifyLinkView] Error: {str(e)}\n{traceback.format_exc()}")
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error')
            return redirect('accounts:verify_email')

    def _clear_old_messages(self, conn, user_key, exclude_tags=None):
        try:
            existing_messages = conn.hgetall(user_key)
            for msg_id, msg_data in existing_messages.items():
                try:
                    parts = msg_data.decode('utf-8', errors='ignore').split('|')
                    if len(parts) != 3:
                        logger.error(f"[EmailVerifyLinkView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {msg_data}")
                        conn.hdel(user_key, msg_id)
                        continue
                    tags = parts[1]
                    expires_at = float(parts[2])
                    if expires_at < now().timestamp() * 1000:
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[EmailVerifyLinkView] Deleted expired message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                        continue
                    if exclude_tags and any(tag in tags for tag in exclude_tags):
                        continue
                    conn.hdel(user_key, msg_id)
                    logger.debug(f"[EmailVerifyLinkView] Deleted message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                except (UnicodeDecodeError, IndexError, ValueError) as e:
                    logger.error(f"[EmailVerifyLinkView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {str(e)}")
                    conn.hdel(user_key, msg_id)
        except Exception as e:
            logger.error(f"[EmailVerifyLinkView] Error clearing old messages from {user_key}: {str(e)}\n{traceback.format_exc()}")


class VerifyEmailView(RateLimitMixin, LoginRequiredMixin, View):
    template_name = 'accounts/verify-email.html'
    rate = '3/5m'
    key = 'user'
    rate_limit_methods = ['POST']

    def _clear_old_messages(self, conn, user_key, exclude_tags=None):
        try:
            existing_messages = conn.hgetall(user_key)
            for msg_id, msg_data in existing_messages.items():
                try:
                    parts = msg_data.decode('utf-8').split('|')
                    if len(parts) != 3:
                        logger.error(f"[VerifyEmailView] Invalid message format in {user_key} for msg_id {msg_id}: {msg_data}")
                        conn.hdel(user_key, msg_id)
                        continue
                    tags = parts[1]
                    expires_at = float(parts[2])
                    if expires_at < time.time() * 1000:
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[VerifyEmailView] Deleted expired message {msg_id} from {user_key}")
                        continue
                    if exclude_tags and any(tag in tags for tag in exclude_tags):
                        continue
                    conn.hdel(user_key, msg_id)
                    logger.debug(f"[VerifyEmailView] Deleted message {msg_id} from {user_key}")
                except (ValueError, IndexError) as e:
                    logger.error(f"[VerifyEmailView] Invalid message format in {user_key} for msg_id {msg_id}: {str(e)}")
                    conn.hdel(user_key, msg_id)
        except Exception as e:
            logger.error(f"[VerifyEmailView] Error clearing old messages from {user_key}: {str(e)}")
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error')

    def _add_error_message(self, conn, user_key, message_text, error_details=""):
        try:
            self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt'])
            message_id = f"msg-error-{self.request.user.id}-{int(time.time())}"
            expires_at = int((time.time() + 5 * 60) * 1000)
            message_data = f"{message_text}|persistent error|{expires_at}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 5 * 60)
            messages.error(self.request, message_text, extra_tags='persistent error')
            logger.error(f"[VerifyEmailView] Error message added: {message_text}, Details: {error_details}")
        except Exception as e:
            logger.error(f"[VerifyEmailView] Error adding error message to {user_key}: {str(e)}")
            messages.error(self.request, message_text, extra_tags='error')

    def get(self, request):
        logger.debug(f"[VerifyEmailView] Handling GET for user {request.user.id}")
        try:
            if not request.user.is_authenticated:
                logger.error("[VerifyEmailView] User is not authenticated")
                return HttpResponseRedirect(reverse_lazy('account_login'))
            user_key = f"persistent_messages:{request.user.id}"  # Define user_key here
            conn = get_redis_connection('default')
            try:
                conn.ping()
                logger.debug("[VerifyEmailView] Redis connection successful")
            except Exception as e:
                logger.error(f"[VerifyEmailView] Redis connection failed: {str(e)}")
                self._add_error_message(conn, user_key, _("Failed to connect to Redis. Please try again."), str(e))
                return render(request, self.template_name, {'form': EmailVerificationForm()})
            try:
                existing_code = EmailVerificationCode.objects.filter(
                    user=request.user,
                    is_for_token=False
                ).first()
            except Exception as e:
                logger.error(f"[VerifyEmailView] Error querying EmailVerificationCode: {str(e)}")
                self._add_error_message(conn, user_key, _("Error accessing verification code. Please try again."), str(e))
                return render(request, self.template_name, {'form': EmailVerificationForm()})
            if existing_code and existing_code.is_locked_out():
                ttl = int((existing_code.lockout_until - now()).total_seconds())
                expires_at = int((time.time() + ttl) * 1000)
                self._clear_old_messages(conn, user_key, exclude_tags=['retry-attempt'])
                message_id = f"msg-rate-limit-{request.user.id}-{int(time.time())}"
                message_text = _("Too many incorrect attempts. Please try again in <span class='timer'></span>.")
                message_data = f"{message_text}|persistent warning rate-limit|{expires_at}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, ttl)
                messages.warning(self.request, message_text, extra_tags='persistent warning rate-limit')
                logger.debug(f"[VerifyEmailView] User {request.user.id}: Lockout active, TTL={ttl}s")
                return render(request, self.template_name, {'form': None})
            if not existing_code or existing_code.is_expired():
                try:
                    expires_at = create_and_send_verification_code(request.user, is_for_token=False)
                    logger.debug(f"[VerifyEmailView] Verification code sent for user {request.user.id}, expires at {expires_at}")
                    self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt'])
                    message_id = f"msg-code-sent-{request.user.id}-{int(time.time())}"
                    message_text = _('A 10-digit verification code has been sent to your email (valid for 5 minutes, remaining: <span class="timer"></span>).')
                    message_data = f"{message_text}|persistent info code-verification|{expires_at}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, int((expires_at - time.time() * 1000) / 1000))
                    messages.info(self.request, message_text, extra_tags='persistent info code-verification')
                except ValueError as e:
                    logger.debug(f"[VerifyEmailView] Cannot send code for user {request.user.id}: {str(e)}")
                    self._add_error_message(conn, user_key, str(e), str(e))
                    return render(request, self.template_name, {'form': None})
                except Exception as e:
                    logger.error(f"[VerifyEmailView] Error sending verification code: {str(e)}")
                    self._add_error_message(conn, user_key, _("Error sending verification code. Please try again."), str(e))
                    return render(request, self.template_name, {'form': EmailVerificationForm()})
            else:
                expires_at = int(existing_code.expires_at.timestamp() * 1000)
                logger.debug(f"[VerifyEmailView] Existing verification code found for user {request.user.id}, expires at {expires_at}")
                self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt'])
                message_id = f"msg-code-existing-{request.user.id}-{int(time.time())}"
                message_text = _('A 10-digit verification code has been sent to your email (valid for 5 minutes, remaining: <span class="timer"></span>).')
                message_data = f"{message_text}|persistent info code-verification|{expires_at}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, int((expires_at - time.time() * 1000) / 1000))
                messages.info(self.request, message_text, extra_tags='persistent info code-verification')
            return render(request, self.template_name, {'form': EmailVerificationForm()})
        except Exception as e:
            logger.error(f"[VerifyEmailView] Unexpected error in GET: {str(e)}")
            user_key = f"persistent_messages:{request.user.id if request.user.is_authenticated else 'anonymous'}"
            try:
                conn = get_redis_connection('default')
                self._add_error_message(conn, user_key, _("An unexpected error occurred. Please try again or contact support."), str(e))
            except:
                messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error')
            return render(request, self.template_name, {'form': EmailVerificationForm()})

    def post(self, request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            logger.error("[VerifyEmailView] User is not authenticated")
            return HttpResponseRedirect(reverse_lazy('account_login'))
        form = EmailVerificationForm(request.POST)
        user_key = f"persistent_messages:{user.id}"
        with get_redis_connection('default') as conn:
            try:
                evc = EmailVerificationCode.objects.filter(user=user, is_for_token=False).first()
                if not evc:
                    self._clear_old_messages(conn, user_key)
                    message_id = f"msg-no-code-{user.id}-{int(time.time())}"
                    message_text = _("No verification code found. Please request a new one <a href='%s'>here</a>.") % reverse_lazy('accounts:verify_email')
                    message_data = f"{message_text}|persistent error code-verification|{int(time.time() * 1000 + 5 * 60 * 1000)}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, 5 * 60)
                    messages.error(self.request, message_text, extra_tags='persistent error code-verification')
                    logger.debug(f"[VerifyEmailView] User {user.id}: No verification code found")
                    return render(request, self.template_name, {'form': form})
                if evc.is_locked_out():
                    ttl = int((evc.lockout_until - now()).total_seconds())
                    expires_at = int((time.time() + ttl) * 1000)
                    self._clear_old_messages(conn, user_key)
                    message_id = f"msg-rate-limit-{user.id}-{int(time.time())}"
                    message_text = _("Too many incorrect attempts. Please try again in <span class='timer'></span>.")
                    message_data = f"{message_text}|persistent warning rate-limit|{expires_at}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, ttl)
                    messages.warning(self.request, message_text, extra_tags='persistent warning rate-limit')
                    logger.debug(f"[VerifyEmailView] User {user.id}: Lockout active, TTL={ttl}s")
                    return render(request, self.template_name, {'form': None})
                if form.is_valid():
                    input_code = form.cleaned_data['code']
                    logger.debug(f"[VerifyEmailView] User {user.id}: Input code={input_code}")
                    if evc.is_for_token:
                        self._clear_old_messages(conn, user_key)
                        message_id = f"msg-wrong-type-{user.id}-{int(time.time())}"
                        message_text = _("This code is for token verification. Please request a 10-digit code <a href='%s'>here</a>.") % reverse_lazy('accounts:verify_email')
                        message_data = f"{message_text}|persistent error code-verification|{int(time.time() * 1000 + 5 * 60 * 1000)}"
                        conn.hset(user_key, message_id, message_data)
                        conn.expire(user_key, 5 * 60)
                        messages.error(self.request, message_text, extra_tags='persistent error code-verification')
                        logger.debug(f"[VerifyEmailView] User {user.id}: Wrong code type")
                        return render(request, self.template_name, {'form': form})
                    if evc.is_expired():
                        self._clear_old_messages(conn, user_key)
                        message_id = f"msg-code-expired-{user.id}-{int(time.time())}"
                        message_text = _("The verification code has expired. Please request a new one <a href='%s'>here</a>.") % reverse_lazy('accounts:verify_email')
                        message_data = f"{message_text}|persistent error code-verification|{int(time.time() * 1000 + 5 * 60 * 1000)}"
                        conn.hset(user_key, message_id, message_data)
                        conn.expire(user_key, 5 * 60)
                        messages.error(self.request, message_text, extra_tags='persistent error code-verification')
                        logger.debug(f"[VerifyEmailView] User {user.id}: Code expired")
                        return render(request, self.template_name, {'form': None})
                    evc.increment_attempts()
                    if evc.code != input_code:
                        remaining_attempts = 3 - evc.attempt_count
                        logger.debug(f"[VerifyEmailView] User {user.id}: Incorrect code, attempt_count={evc.attempt_count}, remaining_attempts={remaining_attempts}")
                        if evc.is_locked_out():
                            ttl = int((evc.lockout_until - now()).total_seconds())
                            expires_at = int((time.time() + ttl) * 1000)
                            self._clear_old_messages(conn, user_key)
                            message_id = f"msg-rate-limit-{user.id}-{int(time.time())}"
                            message_text = _("Too many incorrect attempts. Please try again in <span class='timer'></span>.")
                            message_data = f"{message_text}|persistent warning rate-limit|{expires_at}"
                            conn.hset(user_key, message_id, message_data)
                            conn.expire(user_key, ttl)
                            messages.warning(self.request, message_text, extra_tags='persistent warning rate-limit')
                            logger.debug(f"[VerifyEmailView] User {user.id}: Lockout triggered after incorrect code")
                            return render(request, self.template_name, {'form': None})
                        if remaining_attempts > 0:
                            self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
                            message_id_error = f"msg-invalid-code-{user.id}-{int(time.time())}"
                            message_text_error = _("The entered code is invalid.")
                            message_data_error = f"{message_text_error}|persistent error|{int(time.time() * 1000 + 5 * 60 * 1000)}"
                            conn.hset(user_key, message_id_error, message_data_error)
                            conn.expire(user_key, 5 * 60)
                            messages.error(self.request, message_text_error, extra_tags='persistent error')
                            message_id_retry = f"msg-retry-{user.id}-{int(time.time() + 1)}"
                            message_text_retry = _("You have {} more attempt(s).").format(remaining_attempts)
                            message_data_retry = f"{message_text_retry}|persistent retry-attempt|{int(time.time() * 1000 + 5 * 60 * 1000)}"
                            conn.hset(user_key, message_id_retry, message_data_retry)
                            conn.expire(user_key, 5 * 60)
                            messages.info(self.request, message_text_retry, extra_tags='persistent retry-attempt')
                            if not evc.is_expired():
                                message_id = f"msg-code-existing-{user.id}-{int(time.time() + 2)}"
                                message_text = _("A 10-digit verification code has been sent to your email (valid for <span class='timer'></span>).")
                                message_data = f"{message_text}|persistent info code-verification|{int(evc.expires_at.timestamp() * 1000)}"
                                conn.hset(user_key, message_id, message_data)
                                conn.expire(user_key, int((evc.expires_at - now()).total_seconds()))
                                messages.info(self.request, message_text, extra_tags='persistent info code-verification')
                            logger.debug(f"[VerifyEmailView] User {user.id}: Incorrect code messages sent, remaining_attempts={remaining_attempts}")
                            return render(request, self.template_name, {'form': form})
                    else:
                        user.is_verified = True
                        user.save()
                        evc.delete()
                        self._clear_old_messages(conn, user_key)
                        messages.success(self.request, _("Your email has been verified successfully. You're awesome!"), extra_tags='success')
                        logger.debug(f"[VerifyEmailView] User {user.id}: Email verified successfully")
                        return HttpResponseRedirect(reverse_lazy('accounts:profile_view'))
                else:
                    evc.increment_attempts()
                    remaining_attempts = 3 - evc.attempt_count
                    logger.debug(f"[VerifyEmailView] User {user.id}: Invalid form, attempt_count={evc.attempt_count}, remaining_attempts={remaining_attempts}, form_errors={form.errors}")
                    if evc.is_locked_out():
                        ttl = int((evc.lockout_until - now()).total_seconds())
                        expires_at = int((time.time() + ttl) * 1000)
                        self._clear_old_messages(conn, user_key)
                        message_id = f"msg-rate-limit-{user.id}-{int(time.time())}"
                        message_text = _("Too many incorrect attempts. Please try again in <span class='timer'></span>.")
                        message_data = f"{message_text}|persistent warning rate-limit|{expires_at}"
                        conn.hset(user_key, message_id, message_data)
                        conn.expire(user_key, ttl)
                        messages.warning(self.request, message_text, extra_tags='persistent warning rate-limit')
                        logger.debug(f"[VerifyEmailView] User {user.id}: Lockout triggered after invalid form")
                        return render(request, self.template_name, {'form': None})
                    self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
                    message_id_error = f"msg-invalid-code-{user.id}-{int(time.time())}"
                    message_text_error = _("The entered code is invalid.")
                    message_data_error = f"{message_text_error}|persistent error|{int(time.time() * 1000 + 5 * 60 * 1000)}"
                    conn.hset(user_key, message_id_error, message_data_error)
                    conn.expire(user_key, 5 * 60)
                    messages.error(self.request, message_text_error, extra_tags='persistent error')
                    message_id_retry = f"msg-retry-{user.id}-{int(time.time() + 1)}"
                    message_text_retry = _("You have {} more attempt(s).").format(remaining_attempts)
                    message_data_retry = f"{message_text_retry}|persistent retry-attempt|{int(time.time() * 1000 + 5 * 60 * 1000)}"
                    conn.hset(user_key, message_id_retry, message_data_retry)
                    conn.expire(user_key, 5 * 60)
                    messages.info(self.request, message_text_retry, extra_tags='persistent retry-attempt')
                    if not evc.is_expired():
                        message_id = f"msg-code-existing-{user.id}-{int(time.time() + 2)}"
                        message_text = _("A 10-digit verification code has been sent to your email (valid for <span class='timer'></span>).")
                        message_data = f"{message_text}|persistent info code-verification|{int(evc.expires_at.timestamp() * 1000)}"
                        conn.hset(user_key, message_id, message_data)
                        conn.expire(user_key, int((evc.expires_at - now()).total_seconds()))
                        messages.info(self.request, message_text, extra_tags='persistent info code-verification')
                    return render(request, self.template_name, {'form': form})
            except Exception as e:
                logger.error(f"[VerifyEmailView] Unexpected error in POST: {str(e)}")
                self._add_error_message(conn, user_key, _("An unexpected error occurred. Please try again or contact support."), str(e))
                return render(request, self.template_name, {'form': form})
