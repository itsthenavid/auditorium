from django.db import models
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db.models.constraints import UniqueConstraint
from django.core.validators import FileExtensionValidator, MaxValueValidator

from tinymce.models import HTMLField
from PIL import Image
import io
from django.core.files.base import ContentFile

# Create your models here.

MAX_POST_IMAGES = 10  # Maximum number of images per post

LANGUAGE_CHOICES = (
    ("en", _("English")),
    ("fa", _("Persian")),
    ("ckb", _("Central Kurdish (Sorani)")),
    ("ku", _("Northern Kurdish (Kurmanji)")),
)

DEFAULT_LANGUAGE = "en"

FALLBACK_CHAIN = ['fa', 'ckb', 'ku', 'en']


class TranslationBase(models.Model):
    language = models.CharField(
        verbose_name=_("Language"),
        max_length=10,
        choices=LANGUAGE_CHOICES,
        default=DEFAULT_LANGUAGE,
        db_index=True,
    )
    title = models.CharField(
        verbose_name=_("Title"),
        max_length=255,
        help_text=_("Enter the title."),
    )
    slug = models.SlugField(
        verbose_name=_("Slug"),
        max_length=255,
        unique=True,
        blank=True,
        help_text=_("Enter a unique slug."),
        db_index=True,
    )

    datetime_created = models.DateTimeField(auto_now_add=True, verbose_name=_("Created At"))
    datetime_modified = models.DateTimeField(auto_now=True, verbose_name=_("Updated At"))

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=["language", "slug"]),
        ]

    def __str__(self):
        return f"{self.title} ({self.language})"


class TranslatableBase(models.Model):
    datetime_created = models.DateTimeField(auto_now_add=True, verbose_name=_("Created At"))
    datetime_modified = models.DateTimeField(auto_now=True, verbose_name=_("Updated At"))

    class Meta:
        abstract = True

    def get_translation(self, lang_code=None):
        lang_code = lang_code or getattr(settings, "LANGUAGE_CODE", DEFAULT_LANGUAGE)
        try:
            return self.translations.filter(language=lang_code).first()
        except ObjectDoesNotExist:
            pass

        fallback_qs = self.translations.filter(language__in=FALLBACK_CHAIN).order_by(
            models.Case(
                *[models.When(language=lang, then=models.Value(i)) for i, lang in enumerate(FALLBACK_CHAIN)],
                default=len(FALLBACK_CHAIN)
            )
        )
        return fallback_qs.first()


class Topic(TranslatableBase):
    name = models.CharField(
        verbose_name=_("Topic Name"),
        max_length=255,
        unique=True,
        help_text=_("Enter the topic name."),
        db_index=True,
    )
    description = models.TextField(
        verbose_name=_("Description"),
        blank=True,
        help_text=_("Enter a brief description of the topic."),
    )

    class Meta:
        verbose_name = _("Topic")
        verbose_name_plural = _("Topics")
        indexes = [
            models.Index(fields=["name"]),
        ]

    def __str__(self):
        tr = self.get_translation()
        return tr.title if tr else self.name


class TopicTranslation(TranslationBase):
    topic = models.ForeignKey(
        Topic,
        related_name="translations",
        on_delete=models.CASCADE,
        verbose_name=_("Topic"),
    )

    class Meta:
        constraints = [
            UniqueConstraint(fields=["topic", "language"], name="unique_topic_language"),
            UniqueConstraint(fields=["language", "slug"], name="unique_language_slug_topic"),
        ]
        indexes = [
            models.Index(fields=["topic", "language"]),
        ]
        verbose_name = _("Topic Translation")
        verbose_name_plural = _("Topic Translations")


class Post(TranslatableBase):
    STATUS_CHOICES = (
        (str(1), _("Draft")),
        (str(2), _("Writing")),
        (str(3), _("Review")),
        (str(4), _("Published")),
    )

    topics = models.ManyToManyField(
        Topic,
        related_name="posts",
        verbose_name=_("Topics"),
        blank=True,
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="posts",
        on_delete=models.SET_NULL,
        null=True,
        verbose_name=_("Author"),
        help_text=_("Select the author of the post."),
    )
    datetime_published = models.DateTimeField(
        verbose_name=_("Publish Datetime"),
        null=True,
        blank=True,
        help_text=_("Enter the publish date and time."),
        db_index=True,
    )
    is_active = models.BooleanField(
        verbose_name=_("Is Active"),
        default=True,
        help_text=_("Is this post active?"),
    )
    status = models.CharField(
        verbose_name=_("Status"),
        max_length=1,
        choices=STATUS_CHOICES,
        default=str(1),
        help_text=_("Select the status of the post."),
        db_index=True,
    )
    comment_status = models.BooleanField(
        verbose_name=_("Comments Enabled"),
        default=True,
        help_text=_("Allow comments on this post."),
    )
    discussion_status = models.BooleanField(
        verbose_name=_("Discussion Enabled"),
        default=True,
        help_text=_("Allow discussions on this post."),
    )
    revision_status = models.BooleanField(
        verbose_name=_("Revisions Enabled"),
        default=True,
        help_text=_("Enable revisions for this post."),
    )

    class Meta:
        verbose_name = _("Post")
        verbose_name_plural = _("Posts")
        indexes = [
            models.Index(fields=["datetime_published", "is_active"]),
        ]

    def __str__(self):
        tr = self.get_translation()
        return tr.title if tr else f"Post {self.id}"

    @property
    def is_published(self):
        """Check if the post is published."""
        return self.is_active and self.datetime_published is not None

    @property
    def main_cover(self):
        """Main cover: the first uploaded image."""
        return self.images.order_by("created_at").first()


class PostTranslation(TranslationBase):
    post = models.ForeignKey(
        Post,
        related_name="translations",
        on_delete=models.CASCADE,
        verbose_name=_("Post"),
    )
    excerpt = models.TextField(
        verbose_name=_("Excerpt"),
        blank=True,
        help_text=_("Enter a brief excerpt of the post."),
    )
    content = HTMLField(
        verbose_name=_("Content"),
        blank=True,
        help_text=_("Enter the content of the post."),
    )

    class Meta:
        constraints = [
            UniqueConstraint(fields=["post", "language"], name="unique_post_language"),
            UniqueConstraint(fields=["language", "slug"], name="unique_language_slug_post"),
        ]
        indexes = [
            models.Index(fields=["post", "language"]),
        ]
        verbose_name = _("Post Translation")
        verbose_name_plural = _("Post Translations")

def validate_image_size(value):
    limit = 10 * 1024 * 1024  # 10MB
    if value.size > limit:
        raise ValidationError(_("File size must not exceed 10MB."))


class PostImage(models.Model):
    """
    Post images (optimized with compression and validation).
    """
    post = models.ForeignKey(
        Post,
        related_name="images",
        on_delete=models.CASCADE,
        verbose_name=_("Post"),
    )
    image = models.ImageField(
        upload_to="post_images/",
        verbose_name=_("Image"),
        help_text=_("Upload an image."),
        validators=[
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'webp']),
            validate_image_size,
        ],
    )
    caption = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_("Caption"),
        help_text=_("Enter a caption for the image."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Created At"),
    )

    class Meta:
        indexes = [
            models.Index(fields=["post", "created_at"]),
        ]
        verbose_name = _("Post Image")
        verbose_name_plural = _("Post Images")

    def __str__(self):
        tr = self.post.get_translation()
        return f"Image for {tr.title if tr else self.post.id}"

    def save(self, *args, **kwargs):
        """Compress the image for optimized storage and loading speed."""
        if self.image:
            img = Image.open(self.image)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img.thumbnail((1200, 1200))
            output = io.BytesIO()
            img.save(output, format='WEBP', quality=85)
            self.image = ContentFile(output.getvalue(), self.image.name.rsplit('.', 1)[0] + '.webp')
        super().save(*args, **kwargs)
