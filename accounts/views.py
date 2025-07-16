from django.urls import reverse_lazy
from django.views.generic import UpdateView, TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect
from django.utils.translation import gettext_lazy as _

from allauth.account.views import SignupView

from .forms import RegisterForm, ProfileImageForm, ProfileInfoForm
from .models import User

# Create your views here.


class CustomSignupView(SignupView):
    form_class = RegisterForm
    template_name = 'account/signup.html'

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['language'] = self.kwargs.get('lang_code', self.request.LANGUAGE_CODE)
        return kwargs


class ProfileUpdateView(LoginRequiredMixin, UpdateView):
    model = User
    template_name = 'accounts/profile.html'
    success_url = reverse_lazy('accounts:profile_view')

    def get_form_class(self):
        form_type = self.request.POST.get('form_type')
        print(f"Form type received: {form_type}")  # Debug
        if form_type == 'image':
            return ProfileImageForm
        return ProfileInfoForm

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
        context['info_form'] = ProfileInfoForm(instance=self.request.user, language=self.request.LANGUAGE_CODE)
        return context

    def form_valid(self, form):
        print("Form data received:", self.request.POST)  # Debug
        print("Cleaned form data:", form.cleaned_data)  # Debug
        form.instance.form_type = self.request.POST.get('form_type')
        return super().form_valid(form)

    def form_invalid(self, form):
        print("Form invalid, errors:", form.errors)  # Debug
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
        context['avatar'] = user.avatar.url if user.avatar else '/static/shared/avatars/avatar_1.webp'
        context['banner'] = user.banner.url if user.banner else '/static/shared/banners/default_banner.webp'
        context['username'] = user.username
        context['email'] = user.email
        context['name'] = user.profiles.get(language, {}).get('name', user.username)
        context['bio'] = user.profiles.get(language, {}).get('bio', '')
        context['language'] = language
        return context
