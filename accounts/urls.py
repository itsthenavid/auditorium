from django.urls import path

from .views import ProfileView

# Create your URL addresses here.

urlpatterns = [
    path("profile/", ProfileView.as_view(), name="profile"),
]
