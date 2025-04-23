from django.urls import path

from .views import IndexView, AboutView

# Set your URL paths for the app views' here.

app_name = "pages"

urlpatterns = [
    path("", IndexView.as_view(), name="index"),
    path("about/", AboutView.as_view(), name="about"),
]
