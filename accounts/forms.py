from django import forms
from django.utils.translation import gettext_lazy as _
import random
import logging

from allauth.account.forms import SignupForm

from .models import User, AuditoCode

# Create your forms here.

logger = logging.getLogger(__name__)

class RegisterForm(SignupForm):
    avatar = forms.ImageField(
        label=_("Avatar"),
        required=False,
        help_text=_("Upload a profile picture or use the default random avatar.")
    )
    default_avatar = forms.CharField(
        widget=forms.HiddenInput(),
        required=False
    )
    name = forms.CharField(
        label=_("Name"),
        max_length=100,
        required=False,
    )
    email = forms.EmailField(
        label=_("Email"),
        max_length=100,
        required=False,
    )
    bio = forms.CharField(
        label=_("Bio"),
        widget=forms.Textarea,
        required=False
    )

    def __init__(self, *args, **kwargs):
        self.language = kwargs.pop('language', 'en')
        super().__init__(*args, **kwargs)
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if self.language not in valid_languages:
            self.language = 'en'
        self.fields['name'].label = _(f"Name ({self.get_language_display()})")
        self.fields['bio'].label = _(f"Bio ({self.get_language_display()})")
        if not self.initial.get('default_avatar') and not self.initial.get('avatar'):
            self.initial['default_avatar'] = f"/static/shared/avatars/avatar_{random.randint(1, 20)}.webp"

    def get_language_display(self):
        lang_map = {
            'en': 'English',
            'fa': 'Persian',
            'ckb': 'Central Kurdish',
            'ku': 'Northern Kurdish'
        }
        return lang_map.get(self.language, 'English')

    def clean(self):
        cleaned_data = super().clean()
        avatar = cleaned_data.get('avatar')
        default_avatar = cleaned_data.get('default_avatar')
        if not avatar and not default_avatar:
            cleaned_data['default_avatar'] = f"/static/shared/avatars/avatar_{random.randint(1, 20)}.webp"
        elif not avatar and default_avatar:
            cleaned_data['avatar'] = default_avatar
        else:
            cleaned_data['default_avatar'] = ''
        return cleaned_data

    def save(self, request):
        user = super().save(request)
        language = self.language if self.language != 'en' else getattr(request, 'LANGUAGE_CODE', 'en')
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if language not in valid_languages:
            language = 'en'
        profiles = user.profiles or {}
        profiles[language] = {
            'name': self.cleaned_data['name'],
            'bio': self.cleaned_data['bio']
        }
        user.profiles = profiles
        avatar = self.cleaned_data.get('avatar')
        default_avatar = self.cleaned_data.get('default_avatar')
        if avatar:
            user.avatar = avatar
        elif default_avatar:
            user.avatar = default_avatar
        else:
            user.avatar = f"/static/shared/avatars/avatar_{random.randint(1, 20)}.webp"
        user.save()
        return user


class ProfileImageForm(forms.ModelForm):
    avatar = forms.ImageField(
        label=_("Avatar"),
        required=False,
        help_text=_("Upload a profile picture or use the default random avatar.")
    )
    default_avatar = forms.CharField(
        widget=forms.HiddenInput(),
        required=False
    )
    banner = forms.ImageField(
        label=_("Banner"),
        required=False,
        help_text=_("Upload a banner image for the user profile.")
    )

    class Meta:
        model = User
        fields = ['avatar', 'banner', 'default_avatar']

    def clean(self):
        cleaned_data = super().clean()
        avatar = cleaned_data.get('avatar')
        default_avatar = cleaned_data.get('default_avatar', '')
        banner = cleaned_data.get('banner')
        logger.debug(f"[ProfileImageForm.clean] Start cleaning: avatar={avatar}, default_avatar={default_avatar}, banner={banner}")

        try:
            # Preserve existing avatar if no changes are made
            if not avatar and not default_avatar and self.instance:
                logger.debug(f"[ProfileImageForm.clean] No new avatar or default_avatar provided, preserving existing")
                if self.instance.avatar:
                    cleaned_data['avatar'] = self.instance.avatar
                    cleaned_data['default_avatar'] = ''
                elif self.instance.default_avatar:
                    cleaned_data['avatar'] = self.instance.default_avatar
                    cleaned_data['default_avatar'] = self.instance.default_avatar
                else:
                    random_avatar = f"/static/shared/avatars/avatar_{random.randint(1, 20)}.webp"
                    cleaned_data['avatar'] = random_avatar
                    cleaned_data['default_avatar'] = random_avatar
            # If a new avatar is uploaded
            elif avatar:
                logger.debug(f"[ProfileImageForm.clean] New avatar uploaded: {avatar}")
                cleaned_data['default_avatar'] = ''
            # If a default avatar is selected
            elif default_avatar:
                logger.debug(f"[ProfileImageForm.clean] Using default_avatar: {default_avatar}")
                cleaned_data['avatar'] = default_avatar
            # Fallback (shouldn't reach here, but just in case)
            else:
                logger.debug(f"[ProfileImageForm.clean] Fallback to random default avatar")
                random_avatar = f"/static/shared/avatars/avatar_{random.randint(1, 20)}.webp"
                cleaned_data['avatar'] = random_avatar
                cleaned_data['default_avatar'] = random_avatar

            # Preserve existing banner if no new banner is provided
            if not banner and self.instance and self.instance.banner:
                logger.debug(f"[ProfileImageForm.clean] Preserving existing banner: {self.instance.banner}")
                cleaned_data['banner'] = self.instance.banner

            # Clean paths to avoid /media/media/ issues
            if cleaned_data.get('avatar') and isinstance(cleaned_data['avatar'], str):
                cleaned_data['avatar'] = cleaned_data['avatar'].replace('/media/media/', '/media/').replace('/static/static/', '/static/')
                cleaned_data['default_avatar'] = cleaned_data['default_avatar'].replace('/media/media/', '/media/').replace('/static/static/', '/static/')
                logger.debug(f"[ProfileImageForm.clean] Cleaned avatar path: {cleaned_data['avatar']}")

            logger.debug(f"[ProfileImageForm.clean] Final cleaned data: {cleaned_data}")
            return cleaned_data
        except Exception as e:
            logger.error(f"[ProfileImageForm.clean] Error during cleaning: {str(e)}", exc_info=True)
            raise forms.ValidationError(_("An error occurred while processing the form."))

    def save(self, commit=True):
        try:
            user = super().save(commit=False)
            avatar = self.cleaned_data.get('avatar')
            default_avatar = self.cleaned_data.get('default_avatar')
            banner = self.cleaned_data.get('banner')
            logger.debug(f"[ProfileImageForm.save] avatar={avatar}, default_avatar={default_avatar}, banner={banner}")

            # Update avatar only if changed
            if avatar:
                if isinstance(avatar, str):
                    user.default_avatar = avatar
                    user.avatar = None
                    logger.debug(f"[ProfileImageForm.save] Set default_avatar to: {avatar}")
                else:
                    user.avatar = avatar
                    user.default_avatar = ''
                    logger.debug(f"[ProfileImageForm.save] Set avatar to uploaded file: {avatar}")
            elif default_avatar:
                user.avatar = None
                user.default_avatar = default_avatar
                logger.debug(f"[ProfileImageForm.save] Set default_avatar to: {default_avatar}")
            else:
                # Preserve existing avatar if no changes
                user.avatar = self.instance.avatar
                user.default_avatar = self.instance.default_avatar
                logger.debug(f"[ProfileImageForm.save] Preserved avatar: {user.avatar}, default_avatar: {user.default_avatar}")

            # Update banner only if changed
            if banner:
                user.banner = banner
                logger.debug(f"[ProfileImageForm.save] Set banner to: {banner}")
            else:
                user.banner = self.instance.banner
                logger.debug(f"[ProfileImageForm.save] Preserved banner: {user.banner}")

            if commit:
                user.save()
                logger.debug(f"[ProfileImageForm.save] User {user.id} saved with avatar={user.avatar}, banner={user.banner}, default_avatar={user.default_avatar}")
            return user
        except Exception as e:
            logger.error(f"[ProfileImageForm.save] Error during saving: {str(e)}", exc_info=True)
            raise forms.ValidationError(_("An error occurred while saving the form."))


class ProfileInfoForm(forms.ModelForm):
    username = forms.CharField(
        label=_("Username"),
        max_length=150,
        required=True,
        help_text=_("Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.")
    )
    name = forms.CharField(
        label=_("Name"),
        max_length=100,
        required=False
    )
    email = forms.EmailField(
        label=_("Email"),
        max_length=100,
        required=False
    )
    bio = forms.CharField(
        label=_("Bio"),
        widget=forms.Textarea,
        required=False
    )

    class Meta:
        model = User
        fields = ['username', 'email']

    def __init__(self, *args, **kwargs):
        self.language = kwargs.pop('language', 'en')
        super().__init__(*args, **kwargs)
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if self.language not in valid_languages:
            self.language = 'en'
        self.fields['name'].label = _(f"Name ({self.get_language_display()})")
        self.fields['bio'].label = _(f"Bio ({self.get_language_display()})")
        if self.instance and self.instance.profiles:
            self.initial['name'] = self.instance.profiles.get(self.language, {}).get('name', '')
            self.initial['bio'] = self.instance.profiles.get(self.language, {}).get('bio', '')

    def get_language_display(self):
        lang_map = {
            'en': 'English',
            'fa': 'Persian',
            'ckb': 'Central Kurdish',
            'ku': 'Northern Kurdish'
        }
        return lang_map.get(self.language, 'English')

    def save(self, commit=True):
        user = super().save(commit=False)
        language = self.language
        valid_languages = ['en', 'fa', 'ckb', 'ku']
        if language not in valid_languages:
            language = 'en'
        
        user.username = self.cleaned_data['username']
        

        new_email = self.cleaned_data.get('email', '')
        user.email = new_email

        profiles = user.profiles or {}
        profiles[language] = {
            'name': self.cleaned_data['name'],
            'bio': self.cleaned_data['bio']
        }
        user.profiles = profiles
        if commit:
            user.save()
        return user


class LoginCodeForm(forms.Form):
    code = forms.CharField(
        max_length=15,
        min_length=15,
        label=_("Verification Code"),
        help_text=_("Enter the 15-character code sent to your email.")
    )

    def __init__(self, user, code_type='login', *args, **kwargs):
        self.user = user
        self.code_type = code_type
        super().__init__(*args, **kwargs)

    def clean_code(self):
        code = self.cleaned_data.get('code').upper()
        if len(code) != 15 or not code.isalnum():
            raise forms.ValidationError(_("The code must be exactly 15 alphanumeric characters."))
        try:
            audito_code = AuditoCode.objects.get(
                user=self.user,
                code=code,
                is_used=False,
                type=self.code_type
            )
            if not audito_code.is_valid():
                raise forms.ValidationError(_("The code has expired or is invalid. Please request a new one."))
        except AuditoCode.DoesNotExist:
            raise forms.ValidationError(_("Invalid code."))
        return code


class ProfilePasswordChangeForm(forms.Form):
    """
    Form for changing user password via current password or verification code.
    Validates password requirements and ensures proper error handling.
    """
    current_password = forms.CharField(
        label=_("Current Password"),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': _('Enter your current password')
        }),
        required=False,
        help_text=_("Enter your current password to verify your identity.")
    )
    code = forms.CharField(
        label=_("Verification Code"),
        max_length=15,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': _('Enter the 15-character code sent to your email'),
            'autocomplete': 'off'
        }),
        help_text=_("Enter the code sent to your email (if using code verification).")
    )
    new_password = forms.CharField(
        label=_("New Password"),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': _('Enter new password')
        }),
        required=True,
        min_length=8,
        help_text=_("Password must be at least 8 characters long and contain letters and numbers.")
    )
    confirm_password = forms.CharField(
        label=_("Confirm New Password"),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': _('Confirm your new password')
        }),
        required=True,
        help_text=_("Enter the same password as above for verification.")
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_current_password(self):
        """Validate the current password if provided."""
        current_password = self.cleaned_data.get('current_password')
        if current_password and not self.user.check_password(current_password):
            logger.warning(f"[ProfilePasswordChangeForm] Incorrect current password for user {self.user.id}")
            raise forms.ValidationError(_("Current password is incorrect. Please try again."))
        return current_password

    def clean_code(self):
        """Validate the verification code if provided."""
        code = self.cleaned_data.get('code')
        if code:
            code = code.upper()
            try:
                audito_code = AuditoCode.objects.get(
                    user=self.user,
                    code=code,
                    is_used=False,
                    type='password'
                )
                if not audito_code.is_valid():
                    logger.warning(f"[ProfilePasswordChangeForm] Expired code {code} for user {self.user.id}")
                    raise forms.ValidationError(_("The verification code has expired. Please request a new one."))
            except AuditoCode.DoesNotExist:
                logger.warning(f"[ProfilePasswordChangeForm] Invalid code {code} for user {self.user.id}")
                raise forms.ValidationError(_("Invalid verification code. Please check and try again."))
        return code

    def clean_new_password(self):
        """Validate the new password requirements."""
        new_password = self.cleaned_data.get('new_password')
        if new_password:
            if len(new_password) < 8:
                logger.warning(f"[ProfilePasswordChangeForm] New password too short for user {self.user.id}")
                raise forms.ValidationError(_("Password must be at least 8 characters long."))
            if not any(c.isalpha() for c in new_password):
                logger.warning(f"[ProfilePasswordChangeForm] New password lacks letters for user {self.user.id}")
                raise forms.ValidationError(_("Password must contain at least one letter."))
            if not any(c.isdigit() for c in new_password):
                logger.warning(f"[ProfilePasswordChangeForm] New password lacks numbers for user {self.user.id}")
                raise forms.ValidationError(_("Password must contain at least one number."))
        return new_password

    def clean(self):
        """Validate the combination of fields for password change."""
        cleaned_data = super().clean()
        current_password = cleaned_data.get('current_password')
        code = cleaned_data.get('code')
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')

        logger.debug(f"[ProfilePasswordChangeForm] Cleaning form for user {self.user.id}: current_password={bool(current_password)}, code={bool(code)}")

        # Check if neither current_password nor code is provided
        if not current_password and not code:
            logger.warning(f"[ProfilePasswordChangeForm] Neither current password nor code provided for user {self.user.id}")
            raise forms.ValidationError(_("Please provide either your current password or a verification code."))

        # Check if both current_password and code are provided
        if current_password and code:
            logger.warning(f"[ProfilePasswordChangeForm] Both current password and code provided for user {self.user.id}")
            raise forms.ValidationError(_("Please provide only one of current password or verification code, not both."))

        # Check if new_password matches confirm_password
        if new_password and confirm_password and new_password != confirm_password:
            logger.warning(f"[ProfilePasswordChangeForm] Passwords do not match for user {self.user.id}")
            raise forms.ValidationError(_("The new password and confirmation do not match."))

        # Check if new_password is the same as current_password
        if current_password and new_password and current_password == new_password:
            logger.warning(f"[ProfilePasswordChangeForm] New password same as current for user {self.user.id}")
            raise forms.ValidationError(_("The new password cannot be the same as the current password."))

        return cleaned_data

    def save(self):
        """Save the new password and mark AuditoCode as used if applicable."""
        new_password = self.cleaned_data['new_password']
        code = self.cleaned_data.get('code')
        if code:
            audito_code = AuditoCode.objects.get(user=self.user, code=code.upper(), type='password')
            audito_code.is_used = True
            audito_code.save()
            logger.info(f"[ProfilePasswordChangeForm] Code {code} marked as used for user {self.user.id}")
        self.user.set_password(new_password)
        self.user.save()
        logger.info(f"[ProfilePasswordChangeForm] Password changed successfully for user {self.user.id}")
        return self.user


class EmailVerificationForm(forms.Form):
    code = forms.CharField(
        max_length=10,
        min_length=10,
        label=_("Email Verify Code"),
        help_text=_("Enter the 10-digit verification code sent to your email.")
    )

    def clean_code(self):
        code = self.cleaned_data.get('code')
        if not code.isdigit():
            raise forms.ValidationError(_("The verification code must be exactly 10 digits."))
        return code
