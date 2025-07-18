# Generated by Django 5.2.3 on 2025-06-25 09:15

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_alter_user_options_alter_user_managers_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='avatar',
            field=models.ImageField(default='defaults/avatars/avatar4.webp', help_text='Upload a profile picture for the user.', upload_to='avatars/', verbose_name='Avatar'),
        ),
        migrations.CreateModel(
            name='UserProfileI18n',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('lang_code', models.CharField(choices=[('en', 'English'), ('fa', 'Persian (Farsi)'), ('ckb', 'Central Kurdish (Sorani Kurdish)'), ('ku', 'Northern Kurdish (Kurmanji Kurdish)')], max_length=35)),
                ('name', models.CharField(blank=True, max_length=255)),
                ('bio', models.TextField(blank=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='i18n_profiles', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('user', 'lang_code')},
            },
        ),
        migrations.DeleteModel(
            name='UserTranslation',
        ),
    ]
