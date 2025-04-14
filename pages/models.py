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
        blank=True,
        null=True,
        help_text=_("Upload a header image for the index/home page."),
    )
    about_us_page_header_image = models.ImageField(
        verbose_name=_("About Us Header Image"),
        upload_to="pages/headers/",
        default="defaults/pages/headers/about_us_default_header.webp",
        blank=True,
        null=True,
        help_text=_("Upload a header image for the 'About Us' page."),
    )

    translations = TranslatedFields(
        index_page_title=models.CharField(
            verbose_name=_("'Index/Home' Page Title"),
            max_length=255,
            default=_("Index: Auditorium")
        ),
        index_page_introduction_title = models.CharField(
            verbose_name=_("'Index/Home' Page Introduction Title"),
            max_length=255,
            default=_("HELLO TO THE 'BIG STEPPER.'")
        ),
        index_page_introduction_subtitle = models.CharField(
            verbose_name=_("'Index/Home' Page Introduction Subtitle"),
            max_length=1024,
            default=_("Welcome to AUDITORIUM — a sanctuary, a safe house for thoughts, articles, reflections, and everything your mind dares to put to the paper of this project."),
        ),
        index_page_background_title = models.CharField(
            verbose_name=_("Background Title"),
            max_length=255,
            default=_("GRIEVE & GRIEF"),
            help_text=_("This text will be displayed as a background title."),
        ),
        index_page_moving_slogan_text_1=models.CharField(
            verbose_name=_("Moving Slogan Text"),
            max_length=255,
            default=_("Welcome to Auditorium: The Opinions & Ideas Open Source project."),
            help_text=_("This text will be displayed as a moving slogan. (it's the first one)"),
        ),
        index_page_moving_slogan_text_2=models.CharField(
            verbose_name=_("Moving Slogan Text"),
            max_length=255,
            default=_("Hello to the big stepper, never losing count."),
            help_text=_("This text will be displayed as a moving slogan (it's the second one)."),
        ),
        about_us_page_title=models.CharField(
            verbose_name=_("'About Us' Page Title"),
            max_length=255,
            null=True,
            blank=True,
        ),
        about_us_page_content=RichTextField(
            blank=True,
            null=True
        ),
    )

    is_active = models.BooleanField(
        verbose_name=_("Activation Status"),
        default=False
    )

    def save(self, *args, **kwargs):
        if self.is_active:
            # Deactivate all other active ones
            Page.objects.exclude(pk=self.pk).update(is_active=False)
        super().save(*args, **kwargs)

    def __str__(self):
        title = self.safe_translation_getter("index_page_title", any_language=True)
        
        return str(title or _("(Untitled Page)"))
