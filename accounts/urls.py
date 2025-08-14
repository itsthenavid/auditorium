from django.urls import path

from . import views
from . import api

app_name = 'accounts'

# Create your URLs here.

urlpatterns = [
    path('', views.ProfileUpdateView.as_view(), name='profile_edit_accounts'),
    path('', views.ProfileView.as_view(), name='profile_view_accounts'),
    path('signup/', views.RegisterView.as_view(), name='signup'),
    path('login/', views.CustomLoginView.as_view(), name='account_login'),
    path('profile/', views.ProfileUpdateView.as_view(), name='profile_edit'),
    path('profile/', views.ProfileView.as_view(), name='profile_view'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('email/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('verify-email/<str:key>/', views.EmailVerifyLinkView.as_view(), name='email_verify_link'),
    path('audito-code/', views.SendLoginCodeView.as_view(), name='send_login_code'),
    path('audito-code/verify/', views.VerifyLoginCodeView.as_view(), name='verify_login_code'),
    path('audito-code/resend/', views.ResendLoginCodeView.as_view(), name='resend_login_code'),
    path('api/persistent-messages/', api.persistent_messages, name='persistent_messages'),
]
