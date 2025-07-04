from django.urls import reverse_lazy

from allauth.account.views import SignupView

from .forms import RegisterForm, CustomUserChangeForm
from .models import User

# Create your views here.


class CustomSignupView(SignupView):
    form_class = RegisterForm
    template_name = 'account/signup.html'

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['language'] = self.kwargs.get('lang_code', self.request.LANGUAGE_CODE)
        return kwargs
