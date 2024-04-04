# Generated by Django 4.1.7 on 2024-04-03 00:05

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0007_transaction_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='investment',
            name='daily_return_rate',
            field=models.DecimalField(decimal_places=2, default=10, max_digits=5),
        ),
        migrations.AddField(
            model_name='investment',
            name='duration_days',
            field=models.PositiveIntegerField(default=30),
        ),
        migrations.AddField(
            model_name='investment',
            name='maximum_amount',
            field=models.DecimalField(decimal_places=2, max_digits=10, null=True),
        ),
        migrations.AddField(
            model_name='investment',
            name='minimum_amount',
            field=models.DecimalField(decimal_places=2, max_digits=10, null=True),
        ),
        migrations.CreateModel(
            name='InvestmentSubscription',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subscription_date', models.DateTimeField(default=django.utils.timezone.now)),
                ('end_date', models.DateTimeField()),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('total_return', models.DecimalField(decimal_places=2, default=0, max_digits=10)),
                ('investment_plan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.investment')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]