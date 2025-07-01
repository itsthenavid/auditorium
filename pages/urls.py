from .views import index

from django.urls import path

# URL patterns for the pages app

urlpatterns = [
    path('', index, name='index'),
]
