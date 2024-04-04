# Generated by Django 4.1.7 on 2024-04-02 23:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0006_alter_wallet_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='transaction',
            name='status',
            field=models.CharField(choices=[('pending', 'Pending'), ('done', 'Done'), ('declined', 'Declined')], default='pending', max_length=20),
        ),
    ]