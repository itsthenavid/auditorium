from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class ManagementsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'managements'

    # Human-readable name for the app, used in the admin interface
    verbose_name = _("Managements")

    def ready(self):
        # Import signals to ensure they are registered
        import managements.signals
