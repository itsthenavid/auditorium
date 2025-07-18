from django.apps import AppConfig

from django.utils.translation import gettext_lazy as _


class PagesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pages'

    # This is the verbose name for the app, which will be used in the Django admin interface and other places.
    verbose_name = _('Pages')
