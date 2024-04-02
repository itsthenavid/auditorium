from django.core.files.storage import FileSystemStorage
import os

from django.conf import settings

from urllib.parse import urljoin

# Create your custom project storages here.


class CKEditorFileSystemStorage(FileSystemStorage):
    """Custom storage for django_ckeditor_5 images."""

    location = os.path.join(settings.MEDIA_ROOT, "django_ckeditor_5")
    base_url = urljoin(settings.MEDIA_URL, "django_ckeditor_5/")
