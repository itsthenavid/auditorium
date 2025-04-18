from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class EngineConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'engine'

    verbose_name = _("Engine")
