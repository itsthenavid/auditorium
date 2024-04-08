# Generated by Django 5.0.3 on 2024-04-08 10:11

import django.db.models.deletion
import django.utils.timezone
import taggit.managers
import tinymce.models
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('taggit', '0006_rename_taggeditem_content_type_object_id_taggit_tagg_content_8fc721_idx'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=125, verbose_name='Name')),
                ('slug', models.SlugField(max_length=55, unique=True, verbose_name='Slug')),
                ('description', models.CharField(blank=True, max_length=525, verbose_name='Description')),
                ('datetime_created', models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='Datetime Created')),
                ('datetime_modified', models.DateTimeField(auto_now=True, db_index=True, verbose_name='Datetime Modified')),
                ('is_active', models.BooleanField(default=False, verbose_name='Active')),
            ],
            options={
                'verbose_name': 'Category',
                'verbose_name_plural': 'Categories',
                'ordering': ('is_active', '-datetime_created'),
                'indexes': [models.Index(fields=['datetime_created', 'datetime_modified'], name='clusters_ca_datetim_654813_idx')],
            },
        ),
        migrations.CreateModel(
            name='Article',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('artwork', models.ImageField(default='constants/default_artwork.webp', upload_to='articles/artworks/', verbose_name='Artwork')),
                ('title', models.CharField(max_length=125, verbose_name='Title')),
                ('description', models.CharField(blank=True, max_length=525, verbose_name='Description')),
                ('datetime_created', models.DateTimeField(auto_now_add=True, verbose_name='Datetime Created')),
                ('datetime_modified', models.DateTimeField(auto_now=True, verbose_name='Datetime Modified')),
                ('slug', models.SlugField(max_length=55, verbose_name='Slug')),
                ('publish_datetime', models.DateTimeField(blank=True, db_index=True, default=django.utils.timezone.now, verbose_name='Publish Datetime')),
                ('content', tinymce.models.HTMLField(blank=True, verbose_name='Content')),
                ('status', models.CharField(choices=[('0', 'Draft'), ('1', 'Published')], db_index=True, default='0', max_length=1, verbose_name='Status')),
                ('is_active', models.BooleanField(db_index=True, default=True, verbose_name='Active')),
                ('author', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='user_articles', to=settings.AUTH_USER_MODEL, verbose_name='Author')),
                ('tags', taggit.managers.TaggableManager(help_text='A comma-separated list of tags.', through='taggit.TaggedItem', to='taggit.Tag', verbose_name='Tags')),
                ('category', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='category_articles', to='clusters.category', verbose_name='Article Category')),
            ],
            options={
                'verbose_name': 'Article',
                'verbose_name_plural': 'Articles',
                'ordering': ('is_active', '-publish_datetime'),
                'indexes': [models.Index(fields=['author', 'publish_datetime', 'category', 'status', 'is_active'], name='clusters_ar_author__e65fcc_idx')],
            },
        ),
    ]
