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

    def form_valid(self, form):
        avatar_file = self.request.FILES.get("avatar")
        avatar_default = self.request.POST.get("avatar_default")
        use_default = self.request.POST.get("use_default_avatar") == "true"

        if use_default and avatar_default:
            # Map the submitted path to the storage path
            default_path = avatar_default.replace("/static/en/img/avatars/", "defaults/accounts/avatars/")
            form.instance.avatar = default_path
        elif avatar_file:
            form.instance.avatar = avatar_file
        else:
            # Optionally handle case where no avatar is provided
            pass

        return super().form_valid(form)
