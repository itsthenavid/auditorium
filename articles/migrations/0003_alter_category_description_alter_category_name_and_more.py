# Generated by Django 5.0.3 on 2024-04-01 14:25

import ckeditor_uploader.fields
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('articles', '0002_alter_category_name'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='category',
            name='description',
            field=models.CharField(blank=True, max_length=255, verbose_name='Description'),
        ),
        migrations.AlterField(
            model_name='category',
            name='name',
            field=models.CharField(max_length=125, verbose_name='Name'),
        ),
        migrations.AlterField(
            model_name='category',
            name='slug',
            field=models.SlugField(max_length=55, unique=True, verbose_name='Slug'),
        ),
        migrations.CreateModel(
            name='Article',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('artwork', models.ImageField(default='constants/default_artwork.webp', upload_to='articles/artworks/', verbose_name='Artwork')),
                ('title', models.CharField(max_length=125, verbose_name='Title')),
                ('description', models.CharField(blank=True, max_length=355, verbose_name='Description')),
                ('datetime_created', models.DateTimeField(auto_now_add=True, verbose_name='Datetime Created')),
                ('datetime_modified', models.DateTimeField(auto_now=True, verbose_name='Datetime Modified')),
                ('slug', models.SlugField(max_length=55, verbose_name='Slug')),
                ('publish_datetime', models.DateTimeField(blank=True, db_index=True, default=django.utils.timezone.now, verbose_name='Publish Datetime')),
                ('content', ckeditor_uploader.fields.RichTextUploadingField(blank=True, verbose_name='Content')),
                ('status', models.CharField(choices=[('0', 'Draft'), ('1', 'Published')], db_index=True, default='0', max_length=1, verbose_name='Status')),
                ('is_active', models.BooleanField(db_index=True, default=True, verbose_name='Active')),
                ('author', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='user_articles', to=settings.AUTH_USER_MODEL, verbose_name='Author')),
                ('category', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='category_articles', to='articles.category', verbose_name='Article Category')),
            ],
            options={
                'verbose_name': 'Article',
                'verbose_name_plural': 'Articles',
                'ordering': ('is_active', '-publish_datetime'),
                'indexes': [models.Index(fields=['author', 'publish_datetime', 'category', 'status', 'is_active'], name='articles_ar_author__a1405e_idx')],
            },
        ),
    ]