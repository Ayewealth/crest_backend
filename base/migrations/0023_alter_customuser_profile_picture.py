# Generated by Django 4.1.7 on 2024-04-04 14:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0022_alter_transaction_wallet_address'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='profile_picture',
            field=models.ImageField(blank=True, default='profile-picture', null=True, upload_to='profile_pics'),
        ),
    ]
