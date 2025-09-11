# from django.shortcuts import render
from django.views.generic import UpdateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.translation import gettext_lazy as _
from django.urls import reverse
from django.utils import translation
from django.http import HttpResponseRedirect

from .forms import SettingsForm

# Create your views here.


class SettingsUpdateView(LoginRequiredMixin, UpdateView):
    template_name = 'managements/settings.html'
    form_class = SettingsForm

    def get_object(self, queryset=None):
        return self.request.user.settings

    def form_valid(self, form):
        self.object = form.save()

        new_language = self.object.language

        translation.activate(new_language)
        self.request.LANGUAGE_CODE = new_language
        self.request.session['django_language'] = new_language

        with translation.override(new_language):
            success_url = reverse("managements:settings")

        return HttpResponseRedirect(success_url)
