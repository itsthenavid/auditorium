from .celery import app as celery_app

# This will make sure the app is always imported when

__all__ = ('celery_app',)
