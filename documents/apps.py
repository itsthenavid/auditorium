from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

# This is the configuration file for the 'documents' app.


class DocumentsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'documents'

    # This is the verbose name for the app, which will be used in the admin interface.
    verbose_name = _('Documents')
