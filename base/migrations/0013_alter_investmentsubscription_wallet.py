# Generated by Django 4.1.7 on 2024-04-03 01:06

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0012_investmentsubscription_wallet'),
    ]

    operations = [
        migrations.AlterField(
            model_name='investmentsubscription',
            name='wallet',
            field=models.ForeignKey(default='Bitcoin', on_delete=django.db.models.deletion.CASCADE, to='base.wallet'),
        ),
    ]
