# Generated by Django 4.1.7 on 2024-03-06 13:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0002_customuser_is_verified'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='kyc_verified',
            field=models.BooleanField(default=False),
        ),
    ]
