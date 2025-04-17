from django.shortcuts import render
from django.views.generic import UpdateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy

from .models import UserModel
from .forms import UserProfileForm

# Create your views here.


class ProfileView(LoginRequiredMixin, UpdateView):
    """
    Profile view for updating & showing user profile information.
    This view is accessible only to authenticated users.
    It allows users to update their profile information,
    including avatar, banner, name, username, email, and bio.
    """

    model = UserModel
    form_class = UserProfileForm
    template_name = "accounts/profile.html"
    success_url = reverse_lazy("profile")

    def get_object(self):
        return self.request.user 
