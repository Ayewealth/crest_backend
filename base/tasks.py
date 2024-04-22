from .models import InvestmentSubscription
from django.utils import timezone
from apscheduler.schedulers.background import BackgroundScheduler


def daily_update_total_return():
    # Your task logic here
    subscriptions = InvestmentSubscription.objects.filter(
        end_date__gte=timezone.now())
    for subscription in subscriptions:
        subscription.update_total_return()


scheduler = BackgroundScheduler()
scheduler.add_job(daily_update_total_return, "interval", days=1)

scheduler.start()
