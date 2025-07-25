from django.apps import AppConfig

from django.utils.translation import gettext_lazy as _


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    # This is the verbose name for the app, which will be translated all across the application.
    # It is used in the Django admin interface and other places where the app name is displayed.
    verbose_name = _("Accounts")

    def ready(self):
      import accounts.signals
