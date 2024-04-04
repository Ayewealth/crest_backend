from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import *


@receiver(post_save, sender=CustomUser)
def create_user_wallets(sender, instance, created, **kwargs):
    if created:
        # Define the wallet titles and addresses
        wallet_data = [
            {"title": "Bitcoin",
                "wallet_address": "bc1q9rz6u84p7xvvhnlgdf32k053nk04muavn4q840"},
            {"title": "Ethereum",
                "wallet_address": "0x8cA657729d29720A56A926D1A1EB680717458951"},
            {"title": "XRP", "wallet_address": "rptGrxPxUDwTCkWeaHwiRNQpzfmBYfuSjq"},
            {"title": "USDT Ethereum",
                "wallet_address": "0x8cA657729d29720A56A926D1A1EB680717458951"},
            {"title": "USDT Tron",
                "wallet_address": "TQ6cLZF7HGN9cB5aUAzJ79XGXyhh9ExgcC"}
        ]
        # Create a wallet for each entry in wallet_data
        for data in wallet_data:
            Wallet.objects.create(
                user=instance,
                title=data["title"],
                wallet_address=data["wallet_address"],
                balance=0.00
            )


@receiver(post_save, sender=CustomUser)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
