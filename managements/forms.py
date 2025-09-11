from django import forms
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils.translation import gettext_lazy as _

from .models import Settings

# Create your forms here.

class SettingsForm(forms.ModelForm):
    font_size = forms.IntegerField(
        validators=[MinValueValidator(12), MaxValueValidator(24)],
        help_text=_("Font size in pixels (12-24)"),
    )

    class Meta:
        model = Settings
        fields = ['language', 'theme', 'font_size', 'enable_notifications']
