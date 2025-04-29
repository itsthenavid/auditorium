from django.urls import path

from .views import IndexPageView, IntroductionPageView

# Set your URL paths for the app views' here.

app_name = "pages"

urlpatterns = [
    path("", IndexPageView.as_view(), name="index"),
    path("about/", IntroductionPageView.as_view(), name="introduction"),
]
