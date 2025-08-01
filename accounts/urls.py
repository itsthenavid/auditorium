from django.urls import path

from . import views
from . import api

app_name = 'accounts'

urlpatterns = [
    path('signup/', views.RegisterView.as_view(), name='signup'),
    path('login/', views.CustomLoginView.as_view(), name='account_login'),
    path('profile/', views.ProfileUpdateView.as_view(), name='profile_edit'),
    path('profile/', views.ProfileView.as_view(), name='profile_view'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('email/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('verify-email/<str:key>/', views.EmailVerifyLinkView.as_view(), name='email_verify_link'),
    path('api/persistent-messages/', api.persistent_messages, name='persistent_messages'),
]
