import logging
from django.urls import reverse_lazy
from django.views.generic import UpdateView, TemplateView, View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect
from django.utils.translation import gettext_lazy as _
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.utils.timezone import now
from django_redis import get_redis_connection
from allauth.account.views import SignupView
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC

from .forms import RegisterForm, ProfileImageForm, ProfileInfoForm, EmailVerificationForm
from .models import User, EmailVerificationCode
from extensions.mixins import RateLimitMixin, RequireGetMixin
from extensions.utils import create_and_send_verification_code

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
        """Send confirmation link after successful signup if email is provided."""
        logger.debug("Handling form_valid for CustomSignupView")
        response = super().form_valid(form)  # This sets self.user
        user = self.user  # Use self.user instead of form.user
        if user.email:
            try:
                # Trigger email confirmation link
                email_address = user.emailaddress_set.filter(email=user.email).first()
                if email_address:
                    email_address.send_confirmation(self.request)
                    messages.success(self.request, _("A confirmation link has been sent to your email."))
                else:
                    logger.error(f"No email address found for user {user.id}")
                    messages.error(self.request, _("No email provided. Please use the 10-digit code."))
                    return redirect('accounts:verify_email')
            except Exception as e:
                logger.error(f"Error sending confirmation link: {str(e)}")
                messages.error(self.request, _("Failed to send confirmation link. Please use the 10-digit code."))
                return redirect('accounts:verify_email')
        else:
            logger.debug(f"No email provided for user {user.id}, skipping confirmation")
            messages.info(self.request, _("No email provided. Please use the 10-digit code."))
            return redirect('accounts:verify_email')
        return response

    def form_invalid(self, form):
        messages.error(self.request, _("Invalid signup form. Please try again."))
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
        return super().form_valid(form)

    def form_invalid(self, form):
        logger.debug(f"Form errors: {form.errors}")
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
        context['avatar'] = user.avatar.url if user.avatar else '/static/shared/avatars/avatar_1.webp'
        context['banner'] = user.banner.url if user.banner else '/static/shared/banners/default_banner.webp'
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

        if confirmation:
            time_diff = (now() - confirmation.sent).total_seconds()
            if time_diff > 15 * 60:  # 15 minutes expiration
                messages.error(
                    request,
                    _("Your verification link has expired. Please use the 10-digit code.")
                )
                return redirect('accounts:verify_email')

            confirmation.confirm(request)
            messages.success(request, _("Your email has been verified."))
            return redirect('accounts:profile_view')  # Redirect to profile view page

        messages.error(request, _("Invalid verification link."))
        return redirect('accounts:verify_email')


class VerifyEmailView(RateLimitMixin, LoginRequiredMixin, View):
    """Verify email with a 10-digit code."""
    template_name = 'accounts/verify-email.html'
    rate = '3/5m'
    key = 'user'
    rate_limit_methods = ['GET', 'POST']

    def get(self, request):
        logger.debug("Handling GET for VerifyEmailView")
        try:
            conn = get_redis_connection('default')
            user_key = f"ratelimit:{self.key}:{request.user.id if request.user.is_authenticated else 'anonymous'}"
            count = conn.get(user_key)
            count = int(count) if count else 0
            logger.debug(f"Current request count for {user_key} (GET): {count}")
            limit = int(self.rate.split('/')[0])
            if count < limit:
                create_and_send_verification_code(request.user, is_for_token=False)
                messages.info(request, _("Verification code sent to your email. Please check your inbox."))
            else:
                logger.debug(f"Skipping code send due to rate limit for {user_key}")
        except Exception as e:
            logger.error(f"Error in create_and_send_verification_code: {str(e)}")
            raise
        return render(request, self.template_name, {'form': EmailVerificationForm()})

    def post(self, request, *args, **kwargs):
        logger.debug("Handling POST for VerifyEmailView")
        full_code = ''.join([request.POST.get(f'code_{i}', '') for i in range(10)])
        form = EmailVerificationForm({'code': full_code})

        if form.is_valid():
            input_code = form.cleaned_data['code']
            try:
                evc = request.user.email_verification
                if evc.is_for_token:
                    messages.error(
                        request,
                        _("To verify with a 10-digit code, please go to the designated page.")
                    )
                    return render(request, self.template_name, {'form': form})

                if evc.is_expired():
                    messages.error(
                        request,
                        _("The verification code has expired. Please request a new one.")
                    )
                    return render(request, self.template_name, {'form': form})

                if evc.code == input_code:
                    request.user.is_verified = True
                    request.user.save()
                    evc.delete()
                    messages.success(request, _("Your email has been successfully verified."))
                    return redirect('accounts:profile_view')  # Redirect to profile view page
                else:
                    messages.error(request, _("The entered code is incorrect."))
            except EmailVerificationCode.DoesNotExist:
                messages.error(
                    request,
                    _("No verification code was sent to you. Please try again.")
                )
        else:
            messages.error(request, _("The submitted form is invalid."))
        return render(request, self.template_name, {'form': form})
