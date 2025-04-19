from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.urls import reverse

from accounts.models import UserModel as User
from engine.models import IPAddress

from django_ckeditor_5.fields import CKEditor5Field
from parler.models import TranslatableModel, TranslatedFields

# Create your models here.


class Hall(TranslatableModel):
    """
    Hall model for the documents app.
    This model is used to store the halls in the database
    It uses the TranslatableModel from django-parler to support multiple languages.
    The model has the following fields:
    """

    STATUS_CHOICES = (
        (str(0), _("Idea")),
        (str(1), _("Activated")),
    )

    parent = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        verbose_name=_("Parent"),
        null=True,
        blank=True,
        help_text=_("Parent hall of the current hall."),
        related_name="children",
    )
    artwork = models.ImageField(
        upload_to="documents/halls/",
        verbose_name=_("Artwork"),
        default="documents/halls/default.jpg",
        blank=True,
    )
    translations = TranslatedFields(
        name=models.CharField(
            max_length=255,
            verbose_name=_("Name"),
            help_text=_("Name of the hall."),
        ),
        description=CKEditor5Field(
            verbose_name=_("Description"),
            help_text=_("Description of the hall."),
            config_name='default'
        ),
    )
    slug = models.SlugField(
        max_length=255,
        unique=True,
        verbose_name=_("Slug"),
        help_text=_("Slug for the hall. Used in the URL."),
    )
    creator = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        verbose_name=_("Creator"),
        null=True,
        help_text=_("Creator of the hall."),
    )
    created_datetime = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Created At"),
        help_text=_("Date and time when the hall was created."),
    )
    updated_datetime = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Updated At"),
        help_text=_("Date and time when the hall was last updated."),
    )
    status = models.CharField(
        max_length=1,
        choices=STATUS_CHOICES,
        default=str(0),
        verbose_name=_("Status"),
        help_text=_("Status of the hall."),
    )
    is_active = models.BooleanField(
        default=False,
        verbose_name=_("Activation Status"),
        help_text=_("Is the hall active?"),
    )
    explicit = models.BooleanField(
        default=False,
        verbose_name=_("Explicit Content"),
        help_text=_("Is the hall explicit? Is it has explicit content?"),
    )

    class Meta:
        verbose_name = _("Hall")
        verbose_name_plural = _("Halls")

    def __str__(self):
        """
        String representation of the Hall model.
        Returns the name of the hall.
        """
        return self.name
    
    # def get_absolute_url(self):
    #     """
    #     Returns the URL to access a particular hall instance.
    #     This method is used to create the URL for the hall.
    #     """
    #     return reverse("documents:hall_detail", args=[self.slug])



class Post(TranslatableModel):
    """
    Post model for the documents app.
    This model is used to store the posts in the database.
    It uses the TranslatableModel from django-parler to support multiple languages.
    The model has the following fields:
    - title: The title of the post.
    - content: The content of the post.
    - slug: The slug of the post. This is used to create the URL for the post.
    & more.
    """

    STATUS_CHOICES = (
        (str(0), _("Draft")),
        (str(1), _("Published")),
    )

    artwork = models.ImageField(
        upload_to="documents/artworks/",
        verbose_name=_("Artwork"),
        default="documents/artworks/default.jpg",
        blank=True,
        null=True,
        help_text=_("Artwork for the post."),
    )

    # Translated fields
    translations = TranslatedFields(
        title=models.CharField(
            max_length=255,
            verbose_name=_("Title"),
            help_text=_("Title of the post."),
        ),
        content=CKEditor5Field(
            verbose_name=_("Content"),
            help_text=_("Content of the post."),
            config_name='default'
        ),
    )

    # Fields
    hall = models.ForeignKey(
        Hall,
        on_delete=models.SET_NULL,
        verbose_name=_("Hall"),
        null=True,
        help_text=_("Hall of the post."),
        related_name="hall_posts",
    )
    slug = models.SlugField(
        max_length=255,
        unique=True,
        verbose_name=_("Slug"),
        help_text=_("Slug for the post. Used in the URL."),
    )
    author = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        verbose_name=_("Author"),
        null=True,
        help_text=_("Author of the post."),
    )
    created_datetime = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Created At"),
        help_text=_("Date and time when the post was created."),
    )
    updated_datetime = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Updated At"),
        help_text=_("Date and time when the post was last updated."),
    )
    publish_datetime = models.DateTimeField(
        default=timezone.now,
        verbose_name=_("Published At"),
        help_text=_("Date and time when the post was published."),
    )
    status = models.CharField(
        max_length=1,
        choices=STATUS_CHOICES,
        default=str(0),
        verbose_name=_("Status"),
        help_text=_("Status of the post."),
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name=_("Activation Status"),
        help_text=_("Is the post active?"),
    )
    explicit = models.BooleanField(
        default=False,
        verbose_name=_("Explicit Content"),
        help_text=_("Is the post explicit? Is it has explicit content?"),
    )
    views = models.ManyToManyField(
        IPAddress,
        verbose_name=_("Views"),
        blank=True,
        help_text=_("This field shows how many people watched this post.")
    )

    def publish_if_time_passed(self):
        if self.status == str(0) and timezone.now() >= self.publish_datetime:
            self.status = str(1)
            self.save()

    class Meta:
        verbose_name = _("Post")
        verbose_name_plural = _("Posts")
        ordering = ["-publish_datetime"]

    def __str__(self):
        """
        String representation of the Post model.
        Returns the title of the post.
        """
        return self.title
    
    def get_absolute_url(self):
        """
        Returns the URL to access a particular post instance.
        This method is used to create the URL for the post.
        """
        return reverse("documents:post_detail", args=[self.slug])
    
    def get_translated_title(self):
        """
        Returns the translated title of the post.
        This method is used to get the title of the post in the current language.
        """
        return self.safe_translation_getter("title", any_language=True)
    
    def get_translated_content(self):
        """
        Returns the translated content of the post.
        This method is used to get the content of the post in the current language.
        """
        return self.safe_translation_getter("content", any_language=True)
