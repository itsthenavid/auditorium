from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse_lazy
from django.views.generic import UpdateView, TemplateView, View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect
from django.utils.translation import gettext_lazy as _
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.utils.timezone import now
from django.conf import settings
import time
import logging
import traceback
from django.core.mail import send_mail
import re

from django_redis import get_redis_connection
from allauth.account.views import SignupView, LoginView
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC, EmailAddress
from allauth.account.utils import send_email_confirmation

from extensions.mixins import RateLimitMixin, RequireGetMixin
from extensions.utils import create_and_send_verification_code
from .forms import RegisterForm, ProfileImageForm, ProfileInfoForm, EmailVerificationForm
from .models import User, EmailVerificationCode, LoginCode

# Create your views here.

logger = logging.getLogger(__name__)
User = get_user_model()

class RegisterView(SignupView):
    """
    Handles user registration, extending allauth's SignupView.
    Creates a new user, logs them in, and sends an email verification link only if email is provided.
    """
    template_name = 'account/signup.html'
    form_class = RegisterForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['language'] = self.request.LANGUAGE_CODE or 'en'
        return kwargs

    def form_valid(self, form):
        try:
            logger.debug(f"[RegisterView] Processing signup for email: {form.cleaned_data.get('email')}")
            user = form.save(self.request)
            if not user:
                logger.error("[RegisterView] User creation failed: form.save returned None")
                messages.error(self.request, _("Failed to create account. Please try again."), extra_tags='error')
                return self.form_invalid(form)

            logger.debug(f"[RegisterView] User created: {user.username}, ID: {user.id}")
            login(self.request, user, backend='django.contrib.auth.backends.ModelBackend')
            logger.debug(f"[RegisterView] User {user.username} logged in successfully")

            if user.email:
                try:
                    email_confirmation = send_email_confirmation(self.request, user, signup=True)

                    if isinstance(email_confirmation, EmailConfirmationHMAC):
                        expires_at = int(email_confirmation.expires_at.timestamp() * 1000)
                        logger.debug(f"[RegisterView] Email confirmation sent for user {user.id}, expires at {expires_at}")
                    else:
                        confirmation_timeout = getattr(settings, 'ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS', 15 / (24 * 60)) * 24 * 60 * 60
                        expires_at = int((time.time() + confirmation_timeout) * 1000)
                        logger.warning(f"[RegisterView] EmailConfirmation object not returned, fallback expires_at={expires_at}")

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
                    messages.success(self.request, _("You have successfully signed up, welcome to Auditorium."), extra_tags='success')
                    logger.debug(f"[RegisterView] Message added to Redis: {message_id}, data: {message_data}")

                except Exception as e:
                    logger.error(f"[RegisterView] Error sending email confirmation for user {user.id}: {str(e)}")
                    messages.success(self.request, _("You have successfully signed up, welcome to Auditorium."), extra_tags='success')
                    messages.warning(self.request, _("Yeah! You have successfully signed up, but be careful! You have not entered an email yet."), extra_tags='retry-attempt')
                    messages.error(self.request, _("Error sending verification email. Please try again or request a new code."), extra_tags='error')
            else:
                logger.debug(f"[RegisterView] No email provided for user {user.id}, skipping email confirmation.")
                messages.success(self.request, _("You have successfully signed up, welcome to Auditorium."), extra_tags='success')
                messages.warning(self.request, _("Yeah! You have successfully signed up, but be careful! You have not entered an email yet."), extra_tags='retry-attempt')

            return HttpResponseRedirect(reverse_lazy('accounts:profile_view'))

        except Exception as e:
            logger.error(f"[RegisterView] Unexpected error during signup: {str(e)}")
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error')
            return self.form_invalid(form)

    def form_invalid(self, form):
        logger.debug(f"[RegisterView] Form errors: {form.errors}")
        self.request._messages._queued_messages.clear()
        if '__all__' in form.errors:
            for error in form.errors['__all__']:
                messages.error(self.request, error, extra_tags='error')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    if field == 'username':
                        message = _("This username is already in use.") if 'already exists' in error.lower() else _("The username is not valid/already in use.")
                        messages.warning(self.request, f"{form.fields[field].label}: {message}", extra_tags='warning')
                    elif field == 'email':
                        message = _("This email is already in use.") if 'already exists' in error.lower() else _("The email address is not valid/already in use.")
                        messages.warning(self.request, f"{form.fields[field].label}: {message}", extra_tags='warning')
                    else:
                        messages.error(self.request, f"{form.fields[field].label}: {error}", extra_tags='error')
        form.errors.clear()
        return super().form_invalid(form)

    def _clear_old_messages(self, conn, user_key, exclude_tags=None):
        try:
            existing_messages = conn.hgetall(user_key)
            for msg_id, msg_data in existing_messages.items():
                try:
                    parts = msg_data.decode('utf-8', errors='ignore').split('|')
                    if len(parts) != 3:
                        logger.error(f"[RegisterView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8')}: {msg_data}")
                        conn.hdel(user_key, msg_id)
                        continue
                    tags = parts[1]
                    expires_at = float(parts[2])
                    if expires_at < time.time() * 1000:
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[RegisterView] Deleted expired message {msg_id.decode('utf-8')} from {user_key}")
                        continue
                    if exclude_tags and any(tag in tags for tag in exclude_tags):
                        continue
                    conn.hdel(user_key, msg_id)
                    logger.debug(f"[RegisterView] Deleted message {msg_id.decode('utf-8')} from {user_key}")
                except (ValueError, IndexError) as e:
                    logger.error(f"[RegisterView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8')}: {str(e)}")
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
    """Custom login view to handle form errors with detailed messaging."""
    def form_invalid(self, form):
        """Handle invalid form submission with custom error messages."""
        logger.debug(f"[CustomLoginView] Form errors: {form.errors}")
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
        """Process valid form submission for login."""
        return super().form_valid(form)


class ProfileUpdateView(LoginRequiredMixin, UpdateView):
    """
    Handles updating user profile information or images.
    Supports both ProfileImageForm and ProfileInfoForm based on request data.
    """
    model = User
    template_name = 'accounts/profile.html'
    success_url = reverse_lazy('accounts:profile_view')

    def get_form_class(self):
        """Determine which form class to use based on form_type in POST data."""
        form_type = self.request.POST.get('form_type')
        logger.debug(f"[ProfileUpdateView] Form type received: {form_type}")
        return ProfileImageForm if form_type == 'image' else ProfileInfoForm

    def get_form_kwargs(self):
        """Pass language to ProfileInfoForm if applicable."""
        kwargs = super().get_form_kwargs()
        if self.get_form_class() == ProfileInfoForm:
            kwargs['language'] = self.request.LANGUAGE_CODE
        return kwargs

    def get_object(self):
        """Return the current authenticated user as the object to update."""
        return self.request.user

    def get_context_data(self, **kwargs):
        """Add both image and info forms to the context."""
        context = super().get_context_data(**kwargs)
        context['image_form'] = ProfileImageForm(instance=self.request.user)
        context['info_form'] = ProfileInfoForm(
            instance=self.request.user,
            language=self.request.LANGUAGE_CODE
        )
        logger.debug(f"[ProfileUpdateView] Context prepared: {context}")
        return context

    def post(self, request, *args, **kwargs):
        """Handle POST requests, supporting both AJAX and standard submissions."""
        try:
            form_type = request.POST.get('form_type')
            logger.debug(f"[ProfileUpdateView] POST request received, form_type={form_type}, is_ajax={request.headers.get('X-Requested-With') == 'XMLHttpRequest'}")
            
            self.object = self.get_object()
            form_class = self.get_form_class()
            form = form_class(request.POST, request.FILES, instance=self.object)
            
            if form.is_valid():
                response = self.form_valid(form)
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'status': 'success'})
                return response
            else:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    errors = form.errors.as_json()
                    logger.debug(f"[ProfileUpdateView] Form errors for AJAX: {errors}")
                    return JsonResponse({'status': 'error', 'errors': errors}, status=400)
                return self.form_invalid(form)
        except Exception as e:
            logger.error(f"[ProfileUpdateView] Unexpected error in POST: {str(e)}\n{traceback.format_exc()}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'status': 'error', 'error': str(e)}, status=500)
            return self.form_invalid(form)

    def form_valid(self, form):
        """Process valid form submission, handle changes, and store messages in Redis."""
        logger.debug(f"[ProfileUpdateView] Form data: {self.request.POST}, Files: {self.request.FILES}")
        try:
            user = form.save(commit=False)
            old_user = User.objects.get(id=user.id)
            user._request = self.request
            logger.debug(f"[ProfileUpdateView] Set user._request for user {user.id}")

            conn = get_redis_connection('default')
            user_key = f"persistent_messages:{user.id}"
            self._clear_old_messages(conn, user_key, exclude_tags=['email-verification'])

            if form.__class__ == ProfileImageForm:
                avatar_changed = False
                banner_changed = False

                new_avatar = form.cleaned_data.get('avatar')
                new_default_avatar = form.cleaned_data.get('default_avatar', '')
                old_avatar = old_user.avatar.url if old_user.avatar and hasattr(old_user.avatar, 'url') else old_user.default_avatar or f"{settings.STATIC_URL}shared/avatars/avatar_1.webp"
                avatar_changed_flag = self.request.POST.get('avatar_changed') == 'true'

                logger.debug(f"[ProfileUpdateView] Avatar comparison: new_avatar={new_avatar}, new_default_avatar={new_default_avatar}, old_avatar={old_avatar}, avatar_changed={avatar_changed_flag}")

                if new_avatar and isinstance(new_avatar, str) and (new_avatar != old_avatar or avatar_changed_flag):
                    avatar_changed = True
                    logger.debug(f"[ProfileUpdateView] Avatar changed to default: {new_avatar}")
                    messages.success(self.request, _("Your avatar has been changed"), extra_tags='success avatar transient', fail_silently=True)
                elif new_avatar and not isinstance(new_avatar, str) and (not old_user.avatar or new_avatar != old_user.avatar):
                    avatar_changed = True
                    logger.debug(f"[ProfileUpdateView] Avatar changed to uploaded file: {new_avatar}")
                    messages.success(self.request, _("Your avatar has been changed"), extra_tags='success avatar transient', fail_silently=True)

                new_banner = form.cleaned_data.get('banner')
                old_banner = old_user.banner.url if old_user.banner and hasattr(old_user.banner, 'url') else old_user.banner or f"{settings.STATIC_URL}shared/banners/default_banner.webp"
                
                logger.debug(f"[ProfileUpdateView] Banner comparison: new_banner={new_banner}, old_banner={old_banner}")

                if new_banner and (not old_user.banner or new_banner != old_user.banner):
                    banner_changed = True
                    logger.debug(f"[ProfileUpdateView] Banner changed to uploaded file: {new_banner}")
                    messages.success(self.request, _("Your banner has been changed"), extra_tags='success banner transient', fail_silently=True)

                if not avatar_changed and not banner_changed:
                    logger.debug(f"[ProfileUpdateView] No changes detected for user {user.id}")
                    messages.info(self.request, _("No changes were made to your profile image or banner."), extra_tags='info transient', fail_silently=True)

            elif form.__class__ == ProfileInfoForm:
                language = self.request.LANGUAGE_CODE
                valid_languages = ['en', 'fa', 'ckb', 'ku']
                if language not in valid_languages:
                    language = 'en'
                old_profile = old_user.profiles.get(language, {})

                changes_detected = False

                if 'username' in form.cleaned_data and form.cleaned_data.get('username') != old_user.username:
                    logger.debug(f"[ProfileUpdateView] Username changed from '{old_user.username}' to '{form.cleaned_data.get('username')}'")
                    messages.success(self.request, _(f"Your username has successfully changed to '{form.cleaned_data.get('username')}'"), extra_tags='success transient', fail_silently=True)
                    changes_detected = True

                if 'name' in form.cleaned_data and form.cleaned_data.get('name') != old_profile.get('name', ''):
                    logger.debug(f"[ProfileUpdateView] Name changed from '{old_profile.get('name', '')}' to '{form.cleaned_data.get('name')}'")
                    messages.success(self.request, _(f"Your name has been successfully updated to '{form.cleaned_data.get('name')}'"), extra_tags='success transient', fail_silently=True)
                    changes_detected = True

                if 'bio' in form.cleaned_data and form.cleaned_data.get('bio') != old_profile.get('bio', ''):
                    logger.debug(f"[ProfileUpdateView] Bio changed from '{old_profile.get('bio', '')}' to '{form.cleaned_data.get('bio')}'")
                    messages.success(self.request, _("Your bio has been successfully updated."), extra_tags='success transient', fail_silently=True)
                    changes_detected = True


                if 'email' in form.cleaned_data:
                    new_email = form.cleaned_data.get('email', '')
                    old_email = old_user.email or ''
                    
                    if new_email != old_email:
                        if new_email:
                            logger.debug(f"[ProfileUpdateView] Email changed from '{old_email}' to '{new_email}'")
                            messages.success(self.request, _("Your email has been updated. Please verify your new email."), extra_tags='success transient', fail_silently=True)
                        else:
                            logger.debug(f"[ProfileUpdateView] Email cleared from '{old_email}' to empty")
                            messages.warning(self.request, _("Your email has been removed from your profile."), extra_tags='warning transient', fail_silently=True)
                        changes_detected = True

                if not changes_detected:
                    logger.debug(f"[ProfileUpdateView] No changes detected for user {user.id}")
                    messages.info(self.request, _("No changes were made to your profile information."), extra_tags='info transient', fail_silently=True)

            user.save()
            logger.debug(f"[ProfileUpdateView] User {user.id} saved with avatar={user.avatar}, banner={user.banner}, default_avatar={getattr(user, 'default_avatar', '')}")
            return super().form_valid(form)
        except Exception as e:
            logger.error(f"[ProfileUpdateView] Error in form_valid for user {user.id}: {str(e)}\n{traceback.format_exc()}")
            if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'status': 'error', 'error': str(e)}, status=500)
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error transient', fail_silently=True)
            return self.form_invalid(form)

    def _clear_old_messages(self, conn, user_key, exclude_tags=None):
        """Remove expired or non-excluded messages from Redis for the given user key."""
        try:
            existing_messages = conn.hgetall(user_key)
            for msg_id, msg_data in existing_messages.items():
                try:
                    parts = msg_data.decode('utf-8', errors='ignore').split('|')
                    if len(parts) != 3:
                        logger.error(f"[ProfileUpdateView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {msg_data}")
                        conn.hdel(user_key, msg_id)
                        continue
                    tags = parts[1]
                    expires_at = float(parts[2])
                    if expires_at < time.time() * 1000:
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[ProfileUpdateView] Deleted expired message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                        continue
                    if exclude_tags and any(tag in tags for tag in exclude_tags):
                        continue
                    if 'transient' not in tags:
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[ProfileUpdateView] Deleted message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                except (ValueError, IndexError) as e:
                    logger.error(f"[ProfileUpdateView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {str(e)}")
                    conn.hdel(user_key, msg_id)
        except Exception as e:
            logger.error(f"[ProfileUpdateView] Error clearing old messages from {user_key}: {str(e)}")
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error transient', fail_silently=True)

    def form_invalid(self, form):
        """Handle invalid form submission with detailed error messages."""
        logger.debug(f"[ProfileUpdateView] Form errors: {form.errors}")
        form_type = self.request.POST.get('form_type')
        conn = get_redis_connection('default')
        user_key = f"persistent_messages:{self.request.user.id}"
        try:
            if form_type == 'image':
                for field, errors in form.errors.items():
                    for error in errors:
                        message_text = ""
                        if field == 'avatar':
                            message_text = _("Invalid avatar image. Please upload a valid image (e.g., JPG, PNG).")
                            message_id = f"msg-avatar-error-{self.request.user.id}-{int(now().timestamp())}"
                        elif field == 'banner':
                            message_text = _("Invalid banner image. Please upload a valid image (e.g., JPG, PNG).")
                            message_id = f"msg-banner-error-{self.request.user.id}-{int(now().timestamp())}"
                        else:
                            message_text = _(f"Error in {field}: {error}")
                            message_id = f"msg-field-error-{self.request.user.id}-{int(now().timestamp())}"
                        messages.error(self.request, message_text, extra_tags=f'error {field} transient', fail_silently=True)
            else:
                for field, errors in form.errors.items():
                    for error in errors:
                        message_id = f"msg-{field}-error-{self.request.user.id}-{int(now().timestamp())}"
                        if field == 'username':
                            if 'required' in error.lower():
                                message_text = _("Username is required. Please enter a username.")
                            elif 'already exists' in error.lower():
                                message_text = _("This username is already taken. Please choose a different one.")
                            else:
                                message_text = _("Invalid username. It must be 3-30 characters and contain only letters, numbers, or underscores.")
                        elif field == 'email':
                            if 'invalid' in error.lower():
                                message_text = _("Email format is invalid. Please enter a valid email like example@domain.com.")
                            elif 'already exists' in error.lower():
                                message_text = _("This email is already registered. Please use a different email.")
                            else:
                                message_text = _("Invalid email address. Please check and try again.")
                        elif field == 'name':
                            message_text = _("Invalid name. Please use valid characters.")
                        elif field == 'bio':
                            message_text = _("Invalid bio. Please use valid characters and keep it under 500 characters.")
                        else:
                            message_text = _(f"Error in {field}: {error}")
                        messages.error(self.request, message_text, extra_tags='error transient', fail_silently=True)
            message_id = f"msg-form-error-{self.request.user.id}-{int(now().timestamp())}"
            if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'status': 'error', 'errors': form.errors.as_json()}, status=400)
            return super().form_invalid(form)
        except Exception as e:
            logger.error(f"[ProfileUpdateView] Error in form_invalid: {str(e)}\n{traceback.format_exc()}")
            message_id = f"msg-error-{self.request.user.id}-{int(now().timestamp())}"
            message_text = _("An unexpected error occurred. Please try again or contact support.")
            messages.error(self.request, message_text, extra_tags='error transient', fail_silently=True)
            if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'status': 'error', 'error': str(e)}, status=500)
            return super().form_invalid(form)


class ProfileView(LoginRequiredMixin, TemplateView):
    """
    Displays the user's profile information.
    Fetches user data based on the current language and prepares context for rendering.
    """
    template_name = 'accounts/profile.html'

    def get_context_data(self, **kwargs):
        """Prepare context with user profile data for the current language."""
        context = super().get_context_data(**kwargs)
        user = self.request.user
        language = self.request.LANGUAGE_CODE
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if language not in valid_languages:
            language = 'en'
        context['avatar'] = user.avatar.url if user.avatar and hasattr(user.avatar, 'url') else (user.default_avatar or f"{settings.STATIC_URL}shared/avatars/avatar_1.webp")
        context['banner'] = user.banner.url if user.banner and hasattr(user.banner, 'url') else (user.banner or f"{settings.STATIC_URL}shared/banners/default_banner.webp")
        context['username'] = user.username
        context['email'] = user.email
        context['name'] = user.profiles.get(language, {}).get('name', user.username)
        context['bio'] = user.profiles.get(language, {}).get('bio', '')
        context['language'] = language
        logger.debug(f"[ProfileView] Context prepared for user {user.id}: {context}")
        return context


class EmailVerifyLinkView(RequireGetMixin, View):
    """
    Handles email verification via a link provided in an email.
    Validates the link and updates the user's email verification status.
    """
    
    def dispatch(self, request, *args, **kwargs):
        """Dispatch method to handle rate limiting and user authentication."""
        if request.user.is_authenticated and request.user.is_verified:
            logger.debug(f"[EmailVerifyLinkView] User {request.user.id} is already verified, redirecting to profile")
            messages.info(request, _("Your email is already verified."), extra_tags='info')
            return HttpResponseRedirect(reverse_lazy('accounts:profile_view'))
        elif request.user.email == "" or request.user.email is None:
            logger.debug(f"[EmailVerifyLinkView] User {request.user.id} has no email, redirecting to verify email")
            messages.warning(request, _("You have not entered an email yet. Please enter your email to verify it."), extra_tags='warning')
            return HttpResponseRedirect(reverse_lazy('accounts:profile_edit'))
        
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, key):
        """Process the verification link and confirm the user's email."""
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
                    self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt', 'email-verification'])
                    message_id = f"msg-link-expired-{request.user.id}-{int(now().timestamp())}"
                    message_text = _('The verification link has expired. Please request a 10-digit code <a href="%s">here</a>.') % reverse_lazy('accounts:verify_email')
                    message_data = f"{message_text}|persistent error email-verification|{int(now().timestamp() + 15 * 60 * 1000)}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, 15 * 60)
                    messages.error(self.request, message_text, extra_tags=f'persistent error email-verification')
                    logger.debug(f"[EmailVerifyLinkView] Link expired for user {request.user.id}, message added: {message_id}")
                    return redirect('accounts:verify_email')
                confirmation.confirm(self.request)
                self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt', 'email-verification'])
                message_id = f"msg-email-success-{request.user.id}-{int(now().timestamp())}"
                message_text = _("Your email has been verified successfully. You're awesome!")
                message_data = f"{message_text}|persistent success|{int(now().timestamp() + 5 * 60 * 1000)}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, 5 * 60)
                messages.success(self.request, message_text, extra_tags='persistent success')
                logger.debug(f"[EmailVerifyLinkView] Email verified for user {request.user.id}")
                return redirect('accounts:profile_view')
            self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt', 'email-verification'])
            message_id = f"msg-invalid-link-{request.user.id}-{int(now().timestamp())}"
            message_text = _('The verification link is invalid. Please request a 10-digit code <a href="%s">here</a>.') % reverse_lazy('accounts:verify_email')
            message_data = f"{message_text}|persistent error email-verification|{int(now().timestamp() + 15 * 60 * 1000)}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 15 * 60)
            messages.error(self.request, message_text, extra_tags=f'persistent error email-verification')
            logger.debug(f"[EmailVerifyLinkView] Invalid link for user {request.user.id}, message added: {message_id}")
            return redirect('accounts:verify_email')
        except Exception as e:
            logger.error(f"[EmailVerifyLinkView] Error: {str(e)}\n{traceback.format_exc()}")
            message_id = f"msg-error-{request.user.id}-{int(now().timestamp())}"
            message_text = _("An unexpected error occurred. Please try again or contact support.")
            message_data = f"{message_text}|persistent error|{int(now().timestamp() + 5 * 60 * 1000)}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 5 * 60)
            messages.error(self.request, message_text, extra_tags='persistent error')
            return redirect('accounts:verify_email')

    def _clear_old_messages(self, conn, user_key, exclude_tags=None):
        """Remove expired or non-excluded messages from Redis for the given user key."""
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
                    if 'transient' not in tags:
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[EmailVerifyLinkView] Deleted message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                except (UnicodeDecodeError, IndexError, ValueError) as e:
                    logger.error(f"[EmailVerifyLinkView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {str(e)}")
                    conn.hdel(user_key, msg_id)
        except Exception as e:
            logger.error(f"[EmailVerifyLinkView] Error clearing old messages from {user_key}: {str(e)}\n{traceback.format_exc()}")


class VerifyEmailView(RateLimitMixin, LoginRequiredMixin, View):
    """
    Handles email verification via a 10-digit code sent to the user's email.
    Supports both GET (to request a code) and POST (to verify the code).
    """

    template_name = 'accounts/verify-email.html'
    rate = '3/5m'
    key = 'user'
    rate_limit_methods = ['POST']

    def dispatch(self, request, *args, **kwargs):
        """Dispatch method to handle rate limiting and user authentication."""
        if request.user.is_authenticated and request.user.is_verified:
            logger.debug(f"[EmailVerifyLinkView] User {request.user.id} is already verified, redirecting to profile")
            messages.info(request, _("Your email is already verified."), extra_tags='info')
            return HttpResponseRedirect(reverse_lazy('accounts:profile_view'))
        elif request.user.email == "" or request.user.email is None:
            logger.debug(f"[EmailVerifyLinkView] User {request.user.id} has no email, redirecting to verify email")
            messages.warning(request, _("You have not entered an email yet. Please enter your email to verify it."), extra_tags='warning')
            return HttpResponseRedirect(reverse_lazy('accounts:profile_edit'))
        
        return super().dispatch(request, *args, **kwargs)

    def _clear_old_messages(self, conn, user_key, exclude_tags=None):
        """Remove expired or non-excluded messages from Redis for the given user key."""
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
            message_id = f"msg-error-{self.request.user.id}-{int(now().timestamp())}"
            message_text = _("An unexpected error occurred. Please try again or contact support.")
            message_data = f"{message_text}|persistent error|{int(now().timestamp() + 5 * 60 * 1000)}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 5 * 60)
            messages.error(self.request, message_text, extra_tags='persistent error')

    def _add_error_message(self, conn, user_key, message_text, error_details=""):
        """Add an error message to Redis and Django messages framework."""
        try:
            self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
            message_id = f"msg-error-{self.request.user.id}-{int(time.time())}"
            expires_at = int((time.time() + 5 * 60) * 1000)
            message_data = f"{message_text}|persistent error|{expires_at}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 5 * 60)
            messages.error(self.request, message_text, extra_tags='persistent error')
            logger.error(f"[VerifyEmailView] Error message added: {message_text}, Details: {error_details}")
        except Exception as e:
            logger.error(f"[VerifyEmailView] Error adding error message to {user_key}: {str(e)}")
            messages.error(self.request, message_text, extra_tags='persistent error')

    def get(self, request):
        """Handle GET requests to display the verification form or send a new code."""
        logger.debug(f"[VerifyEmailView] Handling GET for user {request.user.id}")
        try:
            if not request.user.is_authenticated:
                logger.error("[VerifyEmailView] User is not authenticated")
                return HttpResponseRedirect(reverse_lazy('account_login'))
            user_key = f"persistent_messages:{request.user.id}"
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
                self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
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
                    self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
                    message_id = f"msg-code-sent-{request.user.id}-{int(time.time())}"
                    message_text = _('A 10-digit verification code has been sent to your email (valid for 5 minutes, remaining: <span class="timer"></span>).')
                    message_data = f"{message_text}|persistent info code-verification|{expires_at}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, int((expires_at - time.time() * 1000) / 1000))
                    messages.info(self.request, message_text, extra_tags='persistent info code-verification')
                    logger.debug(f"[VerifyEmailView] Message added to Redis: {message_id}, data: {message_data}")
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
                self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
                message_id = f"msg-code-existing-{request.user.id}-{int(time.time())}"
                message_text = _('A 10-digit verification code has been sent to your email (valid for 5 minutes, remaining: <span class="timer"></span>).')
                message_data = f"{message_text}|persistent info code-verification|{expires_at}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, int((expires_at - time.time() * 1000) / 1000))
                messages.info(self.request, message_text, extra_tags='persistent info code-verification')
                logger.debug(f"[VerifyEmailView] Message added to Redis: {message_id}, data: {message_data}")
            return render(request, self.template_name, {'form': EmailVerificationForm()})
        except Exception as e:
            logger.error(f"[VerifyEmailView] Unexpected error in GET: {str(e)}")
            user_key = f"persistent_messages:{request.user.id if request.user.is_authenticated else 'anonymous'}"
            try:
                conn = get_redis_connection('default')
                self._add_error_message(conn, user_key, _("An unexpected error occurred. Please try again or contact support."), str(e))
            except:
                messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='persistent error')
            return render(request, self.template_name, {'form': EmailVerificationForm()})

    def post(self, request, *args, **kwargs):
        """Handle POST requests to verify the submitted email verification code."""
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
                    self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
                    message_id = f"msg-no-code-{user.id}-{int(time.time())}"
                    message_text = _("No verification code found. Please request a new one <a href='%s'>here</a>.") % reverse_lazy('accounts:verify_email')
                    message_data = f"{message_text}|persistent error code-verification|{int(time.time() * 1000 + 5 * 60 * 1000)}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, 5 * 60)
                    messages.error(self.request, message_text, extra_tags='persistent error code-verification')
                    logger.debug(f"[VerifyEmailView] User {user.id}: No verification code found, message added: {message_id}")
                    return render(request, self.template_name, {'form': form})
                if evc.is_locked_out():
                    ttl = int((evc.lockout_until - now()).total_seconds())
                    expires_at = int((time.time() + ttl) * 1000)
                    self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
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
                        self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
                        message_id = f"msg-wrong-type-{user.id}-{int(time.time())}"
                        message_text = _("This code is for token verification. Please request a 10-digit code <a href='%s'>here</a>.") % reverse_lazy('accounts:verify_email')
                        message_data = f"{message_text}|persistent error code-verification|{int(time.time() * 1000 + 5 * 60 * 1000)}"
                        conn.hset(user_key, message_id, message_data)
                        conn.expire(user_key, 5 * 60)
                        messages.error(self.request, message_text, extra_tags='persistent error code-verification')
                        logger.debug(f"[VerifyEmailView] User {user.id}: Wrong code type")
                        return render(request, self.template_name, {'form': form})
                    if evc.is_expired():
                        self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
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
                            self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
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
                            # Only add code-verification message if code is still valid and no recent code-verification message exists
                            existing_messages = conn.hgetall(user_key)
                            has_recent_code_message = any(
                                msg_data.decode('utf-8').split('|')[1].startswith('persistent info code-verification')
                                and float(msg_data.decode('utf-8').split('|')[2]) > time.time() * 1000
                                for msg_data in existing_messages.values()
                            )
                            if not evc.is_expired() and not has_recent_code_message:
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
                        self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
                        message_id = f"msg-email-success-{user.id}-{int(now().timestamp())}"
                        message_text = _("Your email has been verified successfully. You're awesome!")
                        message_data = f"{message_text}|persistent success|{int(now().timestamp() + 5 * 60 * 1000)}"
                        conn.hset(user_key, message_id, message_data)
                        conn.expire(user_key, 5 * 60)
                        messages.success(self.request, message_text, extra_tags='persistent success')
                        logger.debug(f"[VerifyEmailView] User {user.id}: Email verified successfully")
                        return HttpResponseRedirect(reverse_lazy('accounts:profile_view'))
                else:
                    evc.increment_attempts()
                    remaining_attempts = 3 - evc.attempt_count
                    logger.debug(f"[VerifyEmailView] User {user.id}: Invalid form, attempt_count={evc.attempt_count}, remaining_attempts={remaining_attempts}, form_errors={form.errors}")
                    if evc.is_locked_out():
                        ttl = int((evc.lockout_until - now()).total_seconds())
                        expires_at = int((time.time() + ttl) * 1000)
                        self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit'])
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
                    # Only add code-verification message if code is still valid and no recent code-verification message exists
                    existing_messages = conn.hgetall(user_key)
                    has_recent_code_message = any(
                        msg_data.decode('utf-8').split('|')[1].startswith('persistent info code-verification')
                        and float(msg_data.decode('utf-8').split('|')[2]) > time.time() * 1000
                        for msg_data in existing_messages.values()
                    )
                    if not evc.is_expired() and not has_recent_code_message:
                        message_id = f"msg-code-existing-{user.id}-{int(time.time() + 2)}"
                        message_text = _("A 10-digit verification code has been sent to your email (valid for <span class='timer'></span>).")
                        message_data = f"{message_text}|persistent info code-verification|{int(evc.expires_at.timestamp() * 1000)}"
                        conn.hset(user_key, message_id, message_data)
                        conn.expire(user_key, int((evc.expires_at - now()).total_seconds()))
                        messages.info(self.request, message_text, extra_tags='persistent info code-verification')
                    logger.debug(f"[VerifyEmailView] User {user.id}: Invalid form messages sent, remaining_attempts={remaining_attempts}")
                    return render(request, self.template_name, {'form': form})
            except Exception as e:
                logger.error(f"[VerifyEmailView] Unexpected error in POST: {str(e)}")
                self._add_error_message(conn, user_key, _("An unexpected error occurred. Please try again or contact support."), str(e))
                return render(request, self.template_name, {'form': form})


class GetMessagesView(LoginRequiredMixin, View):
    """
    Retrieves persistent messages for the authenticated user from Redis.
    Returns messages as a JSON response for client-side processing.
    """
    def get(self, request):
        """Fetch and return persistent messages for the user."""
        try:
            user_key = f"persistent_messages:{request.user.id}"
            conn = get_redis_connection('default')
            try:
                conn.ping()
                logger.debug("[GetMessagesView] Redis connection successful")
            except Exception as e:
                logger.error(f"[GetMessagesView] Redis connection failed: {str(e)}")
                return JsonResponse({'error': 'Failed to connect to Redis'}, status=500)

            messages_data = []
            existing_messages = conn.hgetall(user_key)
            current_time = time.time() * 1000

            for msg_id, msg_data in existing_messages.items():
                try:
                    parts = msg_data.decode('utf-8', errors='ignore').split('|')
                    if len(parts) != 3:
                        logger.error(f"[GetMessagesView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {msg_data}")
                        conn.hdel(user_key, msg_id)
                        continue
                    message_text, tags, expires_at = parts
                    expires_at = float(expires_at)
                    if expires_at < current_time:
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[GetMessagesView] Deleted expired message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                        continue
                    if 'transient' not in tags:
                        messages_data.append({
                            'id': msg_id.decode('utf-8', errors='ignore'),
                            'text': message_text,
                            'tags': tags.split(),
                            'expires_at': expires_at
                        })
                except (ValueError, IndexError) as e:
                    logger.error(f"[GetMessagesView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {str(e)}")
                    conn.hdel(user_key, msg_id)

            logger.debug(f"[GetMessagesView] Retrieved messages for user {request.user.id}: {messages_data}")
            return JsonResponse({'messages': messages_data}, status=200)
        except Exception as e:
            logger.error(f"[GetMessagesView] Error retrieving messages: {str(e)}\n{traceback.format_exc()}")
            return JsonResponse({'error': 'Failed to load notifications'}, status=500)


class SendLoginCodeView(View):
    """
    Handles the first step of login code authentication.
    Accepts a username or email, validates it, generates a login code, and sends it via email.
    """
    template_name = 'accounts/send_code.html'

    def _is_valid_email(self, email):
        """Validate email format using a regular expression."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def _clear_old_messages(self, conn, user_key, exclude_tags=None, force_clear_tags=None):
        """Remove expired or non-excluded messages from Redis for the given user key.
        Args:
            conn: Redis connection object
            user_key: Redis key for storing messages
            exclude_tags: Tags to preserve (if not expired)
            force_clear_tags: Tags to always remove, regardless of exclude_tags
        """
        try:
            existing_messages = conn.hgetall(user_key)
            for msg_id, msg_data in existing_messages.items():
                try:
                    parts = msg_data.decode('utf-8', errors='ignore').split('|')
                    if len(parts) != 3:
                        logger.error(f"[SendLoginCodeView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {msg_data}")
                        conn.hdel(user_key, msg_id)
                        continue
                    tags = parts[1]
                    expires_at = float(parts[2])
                    # Modified: Force clear messages with force_clear_tags (e.g., code-verification)
                    if force_clear_tags and any(tag in tags for tag in force_clear_tags):
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[SendLoginCodeView] Force deleted message {msg_id.decode('utf-8', errors='ignore')} with tags {tags} from {user_key}")
                        continue
                    if expires_at < time.time() * 1000:
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[SendLoginCodeView] Deleted expired message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                        continue
                    if exclude_tags and any(tag in tags for tag in exclude_tags):
                        continue
                    conn.hdel(user_key, msg_id)
                    logger.debug(f"[SendLoginCodeView] Deleted message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                except (ValueError, IndexError) as e:
                    logger.error(f"[SendLoginCodeView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {str(e)}")
                    conn.hdel(user_key, msg_id)
        except Exception as e:
            logger.error(f"[SendLoginCodeView] Error clearing old messages from {user_key}: {str(e)}")
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error transient')

    def _add_error_message(self, conn, user_key, message_text, error_details=""):
        """Add an error message to Redis and Django messages framework."""
        try:
            # Modified: Pass code-verification to force_clear_tags to avoid duplicates
            self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt', 'code-verification'], force_clear_tags=['code-verification'])
            message_id = f"msg-error-{int(time.time())}"
            expires_at = int((time.time() + 5 * 60) * 1000)
            message_data = f"{message_text}|persistent error|{expires_at}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 5 * 60)
            messages.error(self.request, message_text, extra_tags='persistent error')
            logger.error(f"[SendLoginCodeView] Error message added: {message_text}, Details: {error_details}")
        except Exception as e:
            logger.error(f"[SendLoginCodeView] Error adding error message to {user_key}: {str(e)}")
            messages.error(self.request, message_text, extra_tags='persistent error')

    def get(self, request):
        """Check for existing valid login code or render the form for entering username or email."""
        logger.debug("[SendLoginCodeView] Handling GET request")
        # Use session_key for anonymous users to ensure unique Redis key
        if not request.user.is_authenticated:
            if not request.session.session_key:
                request.session.create()
            user_key = f"persistent_messages:{request.session.session_key}"
        else:
            user_key = f"persistent_messages:{request.user.id}"
        
        conn = get_redis_connection('default')
        
        if request.user.is_authenticated:
            logger.debug(f"[SendLoginCodeView] User {request.user.id} is already authenticated, redirecting to profile")
            return HttpResponseRedirect(reverse_lazy('accounts:profile_view'))
        
        user_id = request.session.get('login_user_id')
        if user_id:
            try:
                user = User.objects.get(id=user_id)
                existing_code = LoginCode.objects.filter(user=user, is_used=False).first()
                
                if existing_code and existing_code.is_valid():
                    expires_at = int(existing_code.expires_at.timestamp() * 1000)
                    logger.debug(f"[SendLoginCodeView] Existing valid login code found for user {user.id}, expires at {expires_at}")
                    
                    # Modified: Force clear old code-verification messages
                    self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt', 'code-verification'], force_clear_tags=['code-verification'])
                    message_id = f"msg-code-existing-{user.id}-{int(time.time())}"
                    message_text = _(f'A login code has been sent to {user.email} (valid for 10 minutes, remaining: <span class="timer"></span>).')
                    message_data = f"{message_text}|persistent info code-verification|{expires_at}"
                    conn.hset(user_key, message_id, message_data)
                    conn.expire(user_key, int((expires_at - time.time() * 1000) / 1000))
                    messages.info(self.request, message_text, extra_tags=f'persistent info code-verification {expires_at}')
                    logger.debug(f"[SendLoginCodeView] Message added to Redis: {message_id}, data: {message_data}")
                    
                    return redirect('accounts:verify_login_code')
                else:
                    if existing_code:
                        existing_code.delete()
                        logger.debug(f"[SendLoginCodeView] Deleted expired login code for user {user.id}")
            except User.DoesNotExist:
                del request.session['login_user_id']
                logger.debug("[SendLoginCodeView] Invalid user_id in session, cleared")
        
        return render(request, self.template_name)

    def post(self, request):
        """Process username or email, generate and send a login code."""
        logger.debug("[SendLoginCodeView] Handling POST request")
        # Use session_key for anonymous users
        if not request.user.is_authenticated:
            if not request.session.session_key:
                request.session.create()
            user_key = f"persistent_messages:{request.session.session_key}"
        else:
            user_key = f"persistent_messages:{request.user.id}"
        
        try:
            identifier = request.POST.get('identifier', '').strip()
            conn = get_redis_connection('default')

            if not identifier:
                self._add_error_message(conn, user_key, _("Please enter your username or email."))
                return render(request, self.template_name)

            user = None
            if self._is_valid_email(identifier):
                try:
                    user = User.objects.get(email=identifier)
                    logger.debug(f"[SendLoginCodeView] Found user by email: {identifier}")
                except User.DoesNotExist:
                    self._add_error_message(conn, user_key, _("No user found with this email."))
                    return render(request, self.template_name)
            else:
                try:
                    user = User.objects.get(username=identifier)
                    if not user.email:
                        self._add_error_message(conn, user_key, _("This user has not registered an email."))
                        return render(request, self.template_name)
                    logger.debug(f"[SendLoginCodeView] Found user by username: {identifier}")
                except User.DoesNotExist:
                    self._add_error_message(conn, user_key, _("No user found with this username."))
                    return render(request, self.template_name)

            existing_code = LoginCode.objects.filter(user=user, is_used=False).first()
            if existing_code and existing_code.is_valid():
                expires_at = int(existing_code.expires_at.timestamp() * 1000)
                logger.debug(f"[SendLoginCodeView] Valid login code already exists for user {user.id}, expires at {expires_at}")
                
                request.session['login_user_id'] = user.id
                # Modified: Force clear old code-verification messages
                self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt', 'code-verification'], force_clear_tags=['code-verification'])
                message_id = f"msg-code-existing-{user.id}-{int(time.time())}"
                message_text = _(f'A login code has been sent to {user.email} (valid for 10 minutes, remaining: <span class="timer"></span>).')
                message_data = f"{message_text}|persistent info code-verification|{expires_at}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, int((expires_at - time.time() * 1000) / 1000))
                messages.info(request, message_text, extra_tags=f'persistent info code-verification {expires_at}')
                logger.debug(f"[SendLoginCodeView] Existing code message added to Redis: {message_id}")
                return redirect('accounts:verify_login_code')

            LoginCode.objects.filter(user=user, is_used=False).delete()
            logger.debug(f"[SendLoginCodeView] Deleted expired login codes for user {user.id}")

            login_code = LoginCode.objects.create(user=user)
            logger.debug(f"[SendLoginCodeView] Created login code for user {user.id}: {login_code.code}")

            try:
                send_mail(
                    subject=_('Your Login Code'),
                    message=_(
                        f'Hello {user.username},\n\n'
                        f'Your login code is: {login_code.code}\n\n'
                        f'This code is valid for 10 minutes.\n\n'
                        f'If you did not request this code, please ignore this email.'
                    ),
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
                logger.debug(f"[SendLoginCodeView] Login code sent to {user.email}")

                request.session['login_user_id'] = user.id
                expires_at = int(login_code.expires_at.timestamp() * 1000)
                # Modified: Force clear old code-verification messages
                self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt', 'code-verification'], force_clear_tags=['code-verification'])
                message_id = f"msg-code-sent-{user.id}-{int(time.time())}"
                message_text = _(f'A login code has been sent to {user.email} (valid for 10 minutes, remaining: <span class="timer"></span>).')
                message_data = f"{message_text}|persistent info code-verification|{expires_at}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, int((expires_at - time.time() * 1000) / 1000))
                messages.info(request, message_text, extra_tags=f'persistent info code-verification {expires_at}')
                logger.debug(f"[SendLoginCodeView] Success message added to Redis: {message_id}")
                return redirect('accounts:verify_login_code')
            except Exception as e:
                logger.error(f"[SendLoginCodeView] Error sending login code to {user.email}: {str(e)}")
                self._add_error_message(conn, user_key, _("Error sending login code. Please try again."), str(e))
                return render(request, self.template_name)
        except Exception as e:
            logger.error(f"[SendLoginCodeView] Unexpected error in POST: {str(e)}\n{traceback.format_exc()}")
            try:
                conn = get_redis_connection('default')
                self._add_error_message(conn, user_key, _("An unexpected error occurred. Please try again or contact support."), str(e))
            except:
                messages.error(request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='persistent error')
            return render(request, self.template_name)


class VerifyLoginCodeView(View):
    """
    Handles the second step of login code authentication.
    Validates the submitted login code and logs in the user if valid.
    """
    template_name = 'accounts/verify_code.html'

    def _clear_old_messages(self, conn, user_key, exclude_tags=None, force_clear_tags=None):
        """Remove expired or non-excluded messages from Redis for the given user key.
        Args:
            conn: Redis connection object
            user_key: Redis key for storing messages
            exclude_tags: Tags to preserve (if not expired)
            force_clear_tags: Tags to always remove, regardless of exclude_tags
        """
        try:
            existing_messages = conn.hgetall(user_key)
            for msg_id, msg_data in existing_messages.items():
                try:
                    parts = msg_data.decode('utf-8', errors='ignore').split('|')
                    if len(parts) != 3:
                        logger.error(f"[VerifyLoginCodeView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {msg_data}")
                        conn.hdel(user_key, msg_id)
                        continue
                    tags = parts[1]
                    expires_at = float(parts[2])
                    # Modified: Force clear messages with force_clear_tags (e.g., code-verification)
                    if force_clear_tags and any(tag in tags for tag in force_clear_tags):
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[VerifyLoginCodeView] Force deleted message {msg_id.decode('utf-8', errors='ignore')} with tags {tags} from {user_key}")
                        continue
                    if expires_at < time.time() * 1000:
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"[VerifyLoginCodeView] Deleted expired message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                        continue
                    if exclude_tags and any(tag in tags for tag in exclude_tags):
                        continue
                    conn.hdel(user_key, msg_id)
                    logger.debug(f"[VerifyLoginCodeView] Deleted message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                except (ValueError, IndexError) as e:
                    logger.error(f"[VerifyLoginCodeView] Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {str(e)}")
                    conn.hdel(user_key, msg_id)
        except Exception as e:
            logger.error(f"[VerifyLoginCodeView] Error clearing old messages from {user_key}: {str(e)}")
            messages.error(self.request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='error transient')

    def _add_error_message(self, conn, user_key, message_text, error_details=""):
        """Add an error message to Redis and Django messages framework."""
        try:
            # Modified: Pass code-verification to force_clear_tags to avoid duplicates
            self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt', 'code-verification'], force_clear_tags=['code-verification'])
            message_id = f"msg-error-{int(time.time())}"
            expires_at = int((time.time() + 5 * 60) * 1000)
            message_data = f"{message_text}|persistent error|{expires_at}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 5 * 60)
            messages.error(self.request, message_text, extra_tags='persistent error')
            logger.error(f"[VerifyLoginCodeView] Error message added: {message_text}, Details: {error_details}")
        except Exception as e:
            logger.error(f"[VerifyLoginCodeView] Error adding error message to {user_key}: {str(e)}")
            messages.error(self.request, message_text, extra_tags='persistent error')

    def get(self, request):
        """Render the form for entering the login code."""
        logger.debug("[VerifyLoginCodeView] Handling GET request")
        # Use session_key for anonymous users
        if not request.user.is_authenticated:
            if not request.session.session_key:
                request.session.create()
            user_key = f"persistent_messages:{request.session.session_key}"
        else:
            user_key = f"persistent_messages:{request.user.id}"
        
        conn = get_redis_connection('default')
        
        user_id = request.session.get('login_user_id')
        if not user_id:
            self._add_error_message(conn, user_key, _("Please enter your email or username first."))
            return redirect('accounts:send_login_code')
            
        try:
            user = User.objects.get(id=user_id)
            existing_code = LoginCode.objects.filter(user=user, is_used=False).first()
            
            if not existing_code or not existing_code.is_valid():
                self._add_error_message(conn, user_key, _("Login code has expired. Please request a new one."))
                return redirect('accounts:send_login_code')
            
            expires_at = int(existing_code.expires_at.timestamp() * 1000)
            logger.debug(f"[VerifyLoginCodeView] Valid login code found for user {user.id}, expires at {expires_at}")
            
            # Modified: Force clear old code-verification messages
            self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt', 'code-verification'], force_clear_tags=['code-verification'])
            message_id = f"msg-code-timer-{user.id}-{int(time.time())}"
            message_text = _(f'Login code sent to {user.email} (valid for 10 minutes, remaining: <span class="timer"></span>).')
            message_data = f"{message_text}|persistent info code-verification|{expires_at}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, int((expires_at - time.time() * 1000) / 1000))
            messages.info(request, message_text, extra_tags=f'persistent info code-verification {expires_at}')
            
            logger.debug(f"[VerifyLoginCodeView] User found for ID {user_id}")
            return render(request, self.template_name, {'user_email': user.email})
        except User.DoesNotExist:
            self._add_error_message(conn, user_key, _("Error processing request. Please try again."))
            return redirect('accounts:send_login_code')

    def post(self, request):
        """Validate the submitted login code and log in the user if valid."""
        logger.debug("[VerifyLoginCodeView] Handling POST request")
        # Use session_key for anonymous users
        if not request.user.is_authenticated:
            if not request.session.session_key:
                request.session.create()
            user_key = f"persistent_messages:{request.session.session_key}"
        else:
            user_key = f"persistent_messages:{request.user.id}"
        
        conn = get_redis_connection('default')

        user_id = request.session.get('login_user_id')
        if not user_id:
            self._add_error_message(conn, user_key, _("Please enter your email or username first."))
            return redirect('accounts:send_login_code')

        try:
            user = User.objects.get(id=user_id)
            logger.debug(f"[VerifyLoginCodeView] User found for ID {user_id}")
        except User.DoesNotExist:
            self._add_error_message(conn, user_key, _("Error processing request. Please try again."))
            return redirect('accounts:send_login_code')

        entered_code = request.POST.get('code', '').strip().upper()
        if not entered_code:
            self._add_error_message(conn, user_key, _("Please enter the login code."))
            return render(request, self.template_name, {'user_email': user.email})

        try:
            login_code = LoginCode.objects.get(
                user=user,
                code=entered_code,
                is_used=False
            )
            logger.debug(f"[VerifyLoginCodeView] Login code found for user {user.id}: {entered_code}")

            if login_code.is_valid():
                login_code.is_used = True
                login_code.save()
                logger.debug(f"[VerifyLoginCodeView] Login code marked as used for user {user.id}")

                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                logger.debug(f"[VerifyLoginCodeView] User {user.id} logged in successfully")

                # Delete old session-based Redis key after successful login
                old_key = f"persistent_messages:{request.session.session_key}"
                conn.delete(old_key)
                logger.debug(f"[VerifyLoginCodeView] Deleted old Redis key {old_key} after login")

                if 'login_user_id' in request.session:
                    del request.session['login_user_id']
                    logger.debug("[VerifyLoginCodeView] Cleared login_user_id from session")

                self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt', 'code-verification'])
                message_id = f"msg-success-{user.id}-{int(time.time())}"
                message_text = _(f'Welcome back, {user.username}!')
                message_data = f"{message_text}|transient success|{int(time.time() * 1000 + 5 * 60 * 1000)}"
                conn.hset(user_key, message_id, message_data)
                conn.expire(user_key, 5 * 60)
                messages.success(self.request, message_text, extra_tags='transient success')
                return redirect('accounts:profile_view')
            else:
                self._add_error_message(conn, user_key, _("The login code has expired. Please request a new one."))
                return redirect('accounts:send_login_code')
        except LoginCode.DoesNotExist:
            self._add_error_message(conn, user_key, _("The entered code is invalid."))
            return render(request, self.template_name, {'user_email': user.email})
        except Exception as e:
            logger.error(f"[VerifyLoginCodeView] Unexpected error in POST: {str(e)}\n{traceback.format_exc()}")
            self._add_error_message(conn, user_key, _("An unexpected error occurred. Please try again or contact support."), str(e))
            return render(request, self.template_name, {'user_email': user.email})


class ResendLoginCodeView(View):
    """
    Handles resending a login code to the user's email.
    Deletes old codes, generates a new one, and sends it via email.
    Returns a JSON response for AJAX requests.
    """
    def get(self, request):
        """Handle GET requests by redirecting to the send login code view."""
        logger.debug("[ResendLoginCodeView] GET request redirected to send_login_code")
        return redirect('accounts:send_login_code')

    def post(self, request):
        """Generate and send a new login code to the user's email."""
        logger.debug("[ResendLoginCodeView] Handling POST request")
        # Use session_key for anonymous users
        if not request.user.is_authenticated:
            if not request.session.session_key:
                request.session.create()
            user_key = f"persistent_messages:{request.session.session_key}"
        else:
            user_key = f"persistent_messages:{request.user.id}"
        
        conn = get_redis_connection('default')

        user_id = request.session.get('login_user_id')
        if not user_id:
            logger.error("[ResendLoginCodeView] No user_id in session")
            return JsonResponse({'success': False, 'message': _('Error processing request.')}, status=400)

        try:
            user = User.objects.get(id=user_id)
            logger.debug(f"[ResendLoginCodeView] User found for ID {user_id}")
        except User.DoesNotExist:
            logger.error(f"[ResendLoginCodeView] User not found for ID {user_id}")
            self._add_error_message(conn, user_key, _("Error processing request."))
            return JsonResponse({'success': False, 'message': _('Error processing request.')}, status=400)

        try:
            LoginCode.objects.filter(user=user, is_used=False).delete()
            logger.debug(f"[ResendLoginCodeView] Deleted unused login codes for user {user.id}")

            login_code = LoginCode.objects.create(user=user)
            logger.debug(f"[ResendLoginCodeView] Created new login code for user {user.id}: {login_code.code}")

            send_mail(
                subject=_('Your New Login Code'),
                message=_(
                    f'Hello {user.username},\n\n'
                    f'Your new login code is: {login_code.code}\n\n'
                    f'This code is valid for 10 minutes.'
                ),
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user.email],
                fail_silently=False,
            )
            logger.debug(f"[ResendLoginCodeView] New login code sent to {user.email}")

            # Modified: Force clear old code-verification messages
            self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt', 'code-verification'], force_clear_tags=['code-verification'])
            
            message_text_success = _('A new login code has been sent to your email.')
            expires_at = int(login_code.expires_at.timestamp() * 1000)
            message_id_timer = f"msg-code-resent-{user.id}-{int(time.time())}"
            message_text_timer = _(f'A new login code has been sent to {user.email} (valid for 10 minutes, remaining: <span class="timer"></span>).')
            message_data_timer = f"{message_text_timer}|persistent info code-verification|{expires_at}"
            conn.hset(user_key, message_id_timer, message_data_timer)
            conn.expire(user_key, int((expires_at - time.time() * 1000) / 1000))
            messages.info(request, message_text_timer, extra_tags=f'persistent info code-verification {expires_at}')
            
            logger.debug(f"[ResendLoginCodeView] Success message added to Redis: {message_id_timer}")
            return JsonResponse({'success': True, 'message': message_text_success}, status=200)
        except Exception as e:
            logger.error(f"[ResendLoginCodeView] Error sending new login code: {str(e)}\n{traceback.format_exc()}")
            self._add_error_message(conn, user_key, _("Error sending new login code."), str(e))
            return JsonResponse({'success': False, 'message': _('Error sending new login code.')}, status=500)
