from django.urls import path

from . import views
from . import api

# Create your URLs here.

app_name = 'accounts'

urlpatterns = [
    path('signup/', views.CustomSignupView.as_view(), name='signup'),
    path('profile/', views.ProfileUpdateView.as_view(), name='profile_edit'),
    path('profile/', views.ProfileView.as_view(), name='profile_view'),
    path('email/verify/<str:key>/', views.EmailVerifyLinkView.as_view(), name='email_verify_link'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('email/', views.VerifyEmailView.as_view(), name='account_email'),
    path('api/persistent-messages/', api.persistent_messages_api, name='persistent_messages'),
    path('api/delete-persistent-message/', api.persistent_messages_api, name='delete_persistent_message'),
]
