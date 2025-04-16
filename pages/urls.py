from django.urls import path

from .views import IndexView

# Set your URL paths for the app views' here.

urlpatterns = [
    path("", IndexView.as_view(), name="index"),
]
