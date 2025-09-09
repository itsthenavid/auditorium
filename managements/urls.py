from django.urls import path

from . import views

# Create your URL patterns here.

app_name = 'managements'

urlpatterns = [
    path('settings/', views.SettingsUpdateView.as_view(), name='settings'),
]
