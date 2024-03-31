from django.urls import path

from .views import index_page_view

# Create your URLs here.

app_name = "pages"

urlpatterns = [
    path("", index_page_view, name="index"),
]

