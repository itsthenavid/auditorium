from django.apps import AppConfig

from django.utils.translation import gettext_lazy as _


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    # Override the ready method to set the verbose name of the app
    def ready(self):
        # Set the verbose name of the app to be translated
        self.verbose_name = _("Accounts")
