# Generated by Django 5.0.6 on 2024-05-21 00:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0028_remove_customuser_captcha'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='captcha',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
