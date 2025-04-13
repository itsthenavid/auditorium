from django.urls import path

from .views import index

# Set your URL paths for the app views' here.

urlpatterns = [
    path("", index, name="index"),
]
