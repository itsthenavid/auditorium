from django.urls import path

from . import views

# Create a list of URL patterns here.

app_name = "accounts"

urlpatterns = [
    # path("register/", RegisterView.as_view(), name="register"),
    path('signup/', views.CustomSignupView.as_view(), name='account_signup'),
]
