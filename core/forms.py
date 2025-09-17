from django import forms
from django.utils.translation import gettext_lazy as _
from django.utils.text import slugify
from django.utils.translation import get_language
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.conf import settings

from tinymce.widgets import TinyMCE

from .models import Post, PostTranslation, Topic, TopicTranslation

# Create your forms here.


class PostCreateForm(forms.Form):
    name = forms.CharField(
        max_length=255,
        label=_("Post Title"),
        help_text=_("Enter the title."),
        widget=forms.TextInput(attrs={'id': 'name', 'placeholder': _('e.g. My First Post'), 'required': True})
    )
    excerpt = forms.CharField(
        label=_("Excerpt"),
        required=False,
        help_text=_("Enter a brief excerpt of the post."),
        widget=forms.Textarea(attrs={'id': 'description', 'rows': 3, 'placeholder': _('e.g. A brief summary of the post...')})
    )
    slug = forms.SlugField(
        max_length=255,
        required=False,
        label=_("Slug"),
        help_text=_("Enter a unique slug (auto-generated if blank)."),
        widget=forms.TextInput(attrs={'id': 'slug', 'placeholder': _('e.g. my-first-post')})
    )
    datetime_published = forms.DateTimeField(
        required=False,
        label=_("Publish Datetime"),
        help_text=_("Enter the publish date and time."),
        initial=timezone.now,
        widget=forms.DateTimeInput(attrs={'id': 'datetime_published', 'type': 'datetime-local'})
    )
    tags = forms.CharField(
        required=False,
        label=_("Tags"),
        help_text=_("Enter tags separated by commas."),
        widget=forms.TextInput(attrs={'id': 'tags', 'placeholder': _('e.g. art, digital, ...')})
    )
    status = forms.ChoiceField(
        choices=Post.STATUS_CHOICES,
        label=_("Post Status"),
        initial='1',
        widget=forms.Select(attrs={'id': 'status'})
    )
    is_active = forms.BooleanField(
        required=False,
        initial=True,
        label=_("Activation Status"),
        widget=forms.CheckboxInput(attrs={'class': 'rn-check-box-input', 'id': 'putonsale'})
    )
    comment_status = forms.BooleanField(
        required=False,
        initial=True,
        label=_("Comment Status"),
        widget=forms.CheckboxInput(attrs={'class': 'rn-check-box-input', 'id': 'instantsaleprice'})
    )
    revision_status = forms.BooleanField(
        required=False,
        initial=True,
        label=_("Revision Status"),
        widget=forms.CheckboxInput(attrs={'class': 'rn-check-box-input', 'id': 'unlockpurchased'})
    )
    discussion_status = forms.BooleanField(
        required=False,
        initial=True,
        label=_("Discussion Status"),
        widget=forms.CheckboxInput(attrs={'class': 'rn-check-box-input', 'id': 'discussionstatus'})
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        self.language = get_language() or 'en'

    def generate_unique_slug(self, base_slug, language, model=PostTranslation):
        slug = base_slug
        counter = 1
        while model.objects.filter(language=language, slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1
        return slug

    def save(self, commit=True):
        post = Post(
            author=self.user,
            datetime_published=self.cleaned_data['datetime_published'],
            is_active=self.cleaned_data['is_active'],
            status=self.cleaned_data['status'],
            comment_status=self.cleaned_data['comment_status'],
            discussion_status=self.cleaned_data['discussion_status'],
            revision_status=self.cleaned_data['revision_status'],
        )
        if commit:
            post.save()

        slug = self.cleaned_data.get('slug') or slugify(self.cleaned_data.get('name', 'untitled'), allow_unicode=True)
        unique_slug = self.generate_unique_slug(slug, self.language)
        translation = PostTranslation(
            post=post,
            language=self.language,
            title=self.cleaned_data['name'],
            slug=unique_slug,
            excerpt=self.cleaned_data['excerpt'],
        )
        if commit:
            translation.save()

        if self.cleaned_data['tags']:
            tag_names = [t.strip() for t in self.cleaned_data['tags'].split(',') if t.strip()]
            for tag_name in tag_names:
                topic, _ = Topic.objects.get_or_create(name=tag_name)
                topic_slug = slugify(tag_name, allow_unicode=True)
                unique_topic_slug = self.generate_unique_slug(topic_slug, self.language, model=TopicTranslation)
                TopicTranslation.objects.get_or_create(
                    topic=topic,
                    language=self.language,
                    defaults={'title': tag_name, 'slug': unique_topic_slug}
                )
                post.topics.add(topic)

        return post


class PostContentForm(forms.ModelForm):
    class Meta:
        model = PostTranslation
        fields = ['content']
        widgets = {
            'content': TinyMCE(attrs={'cols': 80, 'rows': 30}),
        }

    def __init__(self, *args, **kwargs):
        self.post = kwargs.pop('post', None)
        self.language = kwargs.pop('language', 'en')
        super().__init__(*args, **kwargs)
        
        self.fields['content'].widget.mce_attrs = getattr(settings, 'TINYMCE_DEFAULT_CONFIG', {})

    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.post:
            instance.post = self.post
        if self.language:
            instance.language = self.language
        if not instance.pk and not instance.title:
            instance.title = 'Untitled'
            instance.slug = slugify(instance.title, allow_unicode=True)
        if commit:
            instance.save()
        return instance
