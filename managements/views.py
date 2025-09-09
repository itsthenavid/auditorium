# from django.shortcuts import render
from django.views.generic import UpdateView

# Create your views here.


class SettingsUpdateView(UpdateView):
    template_name = 'managements/settings.html'
    fields = ['language', 'theme']
    success_url = '/'

    def get_object(self, queryset=None):
        # Assuming the user is authenticated
        return self.request.user.settings
