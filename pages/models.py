from django.db import models
from django.utils.translation import gettext_lazy as _

from parler.models import TranslatableModel, TranslatedFields
from ckeditor.fields import RichTextField

# Create your models here.


class Page(TranslatableModel):
    """
    Page model is a base model for informative pages like
    'Index (Home)', 'About Us', 'Contact Us', etc.
    """

    index_page_header_image = models.ImageField(
        verbose_name=_("Main Header Image"),
        upload_to="pages/headers/",
        default="defaults/pages/headers/index_default_header.webp",
        blank=False,
        null=False,
        help_text=_("Upload a header image for the index/home page."),
    )
    about_us_page_header_image = models.ImageField(
        verbose_name=_("About Us Header Image"),
        upload_to="pages/headers/",
        default="defaults/pages/headers/about_us_default_header.webp",
        blank=False,
        null=False,
        help_text=_("Upload a header image for the 'About Us' page."),
    )

    translations = TranslatedFields(
        index_page_title=models.CharField(
            verbose_name=_("'Index/Home' Page Title"),
            max_length=255,
        ),
        index_page_moving_slogan_text=models.CharField(
            verbose_name=_("Moving Slogan Text"),
            max_length=255,
            blank=False,
            null=False,
            help_text=_("This text will be displayed as a moving slogan."),
        ),
        about_us_page_title=models.CharField(
            verbose_name=_("'About Us' Page Title"),
            max_length=255,
        ),
        about_us_page_content=RichTextField(),
    )

    def __str__(self):
        return self.safe_translation_getter("index_page_title", any_language=True)
