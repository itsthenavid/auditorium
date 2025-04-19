from django.db import models
from django.utils.translation import gettext_lazy as _

from parler.models import TranslatableModel, TranslatedFields
from django_ckeditor_5.fields import CKEditor5Field

# Create your models here.


class Page(TranslatableModel):
    """
    Page model is a base model for informative pages like
    'Index (Home)', 'About Us', 'Contact Us', etc.
    """

    index_page_header_image = models.ImageField(
        verbose_name=_("Main Header Image"),
        upload_to="pages/headers/",
        default="defaults/pages/headers/index_default_header_image.webp",
        blank=True,
        null=True,
        help_text=_("Upload a header image for the index/home page."),
    )
    about_page_header_image = models.ImageField(
        verbose_name=_("About Header Image"),
        upload_to="pages/headers/",
        default="defaults/pages/headers/about_default_header_image.webp",
        blank=True,
        null=True,
        help_text=_("Upload a header image for the 'About' page."),
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
        about_page_title=models.CharField(
            verbose_name=_("'About' Page Title"),
            max_length=255,
            null=True,
            blank=True,
        ),
        about_page_introduction_title=models.CharField(
            verbose_name=_("'About' Page Introduction Title"),
            max_length=255,
            null=True,
            blank=True,
            help_text=_("This text will be displayed as the introduction title of the 'About' page."),
        ),
        about_page_introduction_background_title=models.CharField(
            verbose_name=_("'About' Page Background Title"),
            max_length=255,
            null=True,
            blank=True,
            help_text=_("This text will be displayed as the background title of the 'About' page."),
        ),
        about_page_content=CKEditor5Field(
            blank=True,
            null=True,
            verbose_name=_("'About' Page Content"),
            help_text=_("This text will be displayed as the content of the 'About' page."),
        ),
    )

    index_page_sentences = models.ManyToManyField(
        "Sentences",
        verbose_name=_("Index Page Sentences"),
        blank=True,
        help_text=_("These sentences will be displayed on the index page."),
        related_name="index_page_sentences",
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
    

class Sentences(TranslatableModel):
    """
    Sentences model is a base model for informative sentences (for the index page).
    """

    translates = TranslatedFields(
        sentence = models.CharField(
            verbose_name=_("Sentence"),
            max_length=255,
            help_text=_("This text will be displayed as a sentence."),
        ),
        quote_by= models.CharField(
            verbose_name=_("Quote"),
            max_length=255,
            help_text=_("It shows who this passage was quoted from.")
        )
    )

    def __str__(self):
        sentence = self.safe_translation_getter("sentence", any_language=True)
        
        return str(sentence or _("(Untitled Sentence)"))
