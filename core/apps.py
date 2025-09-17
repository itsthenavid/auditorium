from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    # This is the verbose name for the app, which will be translated all across the application.
    # It is used in the Django admin interface and other places where the app name is displayed.
    verbose_name = "Core Application"
