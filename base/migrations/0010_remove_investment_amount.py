# Generated by Django 4.1.7 on 2024-04-03 00:09

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0009_remove_investment_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='investment',
            name='amount',
        ),
    ]
