from django.urls import path

from .views import CustomSignupView, ProfileUpdateView, ProfileView

# Create your URLs here.

app_name = 'accounts'

urlpatterns = [
    path('signup/', CustomSignupView.as_view(), name='signup'),
    path('profile/', ProfileUpdateView.as_view(), name='profile_edit'),
    path('profile/', ProfileView.as_view(), name='profile_view'),
]
