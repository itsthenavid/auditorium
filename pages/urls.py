from .views import index

from django.urls import path

# URL patterns for the pages app

app_name = "pages"

urlpatterns = [
    path('', index, name='index'),
]
