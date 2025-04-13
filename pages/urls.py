from django.urls import path

from .views import IndexPageTemplateView

# Set your URL paths for the app views' here.

urlpatterns = [
    path("", IndexPageTemplateView.as_view(), name="index"),
]

