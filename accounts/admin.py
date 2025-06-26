from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django import forms

from django.utils.translation import gettext_lazy as _

from .models import User, UserProfileI18n

# Register your models here.


class UserProfileI18nForm(forms.ModelForm):
    """
    """
    # 
    class Meta:
        model = UserProfileI18n
        fields = ('lang_code', 'name', 'bio')
        widgets = {
            'name': forms.TextInput(attrs={'style': 'width: 400px'}),
            'bio': forms.Textarea(attrs={'rows': 3, 'cols': 80}),
        }

    def clean_lang_code(self):
        lang = self.cleaned_data['lang_code']
        user = self.instance.user or self.initial.get('user')
        if user and UserProfileI18n.objects.filter(user=user, lang_code=lang).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError(_(f"A translation is already saved for the {lang} language."))
        return lang


class UserProfileI18nInline(admin.TabularInline):
    """
    """
    # 
    model = UserProfileI18n
    form = UserProfileI18nForm
    extra = 0
    min_num = 1
    max_num = 4
    fields = ('lang_code', 'name', 'bio')
    verbose_name_plural = _("The translation for the different languages.")
    show_change_link = False

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    """
    # 
    inlines = [UserProfileI18nInline]
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Avatar', {'fields': ('avatar',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    list_display = ('username', 'is_staff', 'is_active')
    search_fields = ('username', 'email')
    ordering = ('-date_joined',)

@admin.register(UserProfileI18n)
class UserProfileI18nAdmin(admin.ModelAdmin):
    """
    """
    # 
    list_display = ('user', 'lang_code', 'short_name')
    list_filter = ('lang_code',)
    search_fields = ('user__username', 'name', 'bio')

    def short_name(self, obj):
        return obj.name[:40] + "..." if obj.name else "-"
    short_name.short_description = _("Name")
