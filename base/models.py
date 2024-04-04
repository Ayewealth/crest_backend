from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

# Create your models here.


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    # Profile picture field
    profile_picture = models.ImageField(
        upload_to='profile_pics', default='default.png')

    # User Detail fields
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    email = models.EmailField(unique=True)

    # Kyc related fields
    identification_type = models.CharField(max_length=50, blank=True, choices=[(
        "national_id", "National ID"), ("passport", "International Passport")])
    identification_document = models.ImageField(
        upload_to='kyc', blank=True, null=True)
    address_document_type = models.CharField(max_length=50, blank=True, choices=[("utility_bill", "Utility Bill"), (
        "bank_reference", "Bank Reference"), ("proof_of_residence", "Proof of Residence"), ("permit", "Driver or Residence Permit")])
    address_document = models.ImageField(
        upload_to='kyc', blank=True, null=True)

    is_verified = models.BooleanField(default=False)
    kyc_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def __str__(self):
        return self.email


class Wallet(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    wallet_address = models.CharField(max_length=255)
    balance = models.DecimalField(
        max_digits=10, decimal_places=2, default=0.00)

    def __str__(self):
        return f"{self.user.email} - {self.title} Wallet"


class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ('deposit', 'Deposit'),
        ('withdrawal', 'Withdrawal'),
    ]
    STATUS = [
        ('pending', 'Pending'),
        ('done', 'Done'),
        ('declined', 'Declined')
    ]
    transaction_type = models.CharField(
        max_length=20, choices=TRANSACTION_TYPES)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True)
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE)
    wallet_address = models.CharField(max_length=255, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS, default="pending")
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.first_name} {self.transaction_type}"


class Investment(models.Model):
    PLAN_CHOICES = [
        ('basic', 'Basic'),
        ('standard', 'Standard'),
        ('regular', 'Regular'),
        ('premium', 'Premium'),
    ]
    plan = models.CharField(max_length=100, choices=PLAN_CHOICES)
    daily_return_rate = models.DecimalField(
        max_digits=5, decimal_places=2, default=10)
    duration_days = models.PositiveIntegerField(default=30)
    minimum_amount = models.DecimalField(
        max_digits=10, decimal_places=2, null=True)
    maximum_amount = models.DecimalField(
        max_digits=10, decimal_places=2, null=True)

    def __str__(self):
        return self.plan


class InvestmentSubscription(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    investment_plan = models.ForeignKey(Investment, on_delete=models.CASCADE)
    subscription_date = models.DateTimeField(default=timezone.now)
    wallet = models.ForeignKey(
        Wallet, on_delete=models.CASCADE, default=1, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    total_return = models.DecimalField(
        max_digits=10, decimal_places=2, default=0)
    end_date = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        # Calculate the end date based on subscription date and investment duration (30 days)
        self.end_date = self.subscription_date + timezone.timedelta(days=30)
        super().save(*args, **kwargs)

    def calculate_daily_return(self):
        # Calculate the daily return based on the amount invested and the daily return rate
        daily_return = (self.amount *
                        self.investment_plan.daily_return_rate) / 100
        return daily_return

    def update_total_return(self):
        # Update the total return every day by adding the daily return
        days_passed = (timezone.now() - self.subscription_date).days
        if days_passed <= self.investment_plan.duration_days:
            daily_return = self.calculate_daily_return()
            self.total_return += daily_return
            self.save()
            return True
        return False

    def __str__(self):
        return f"{self.user.email} - {self.investment_plan.plan}"


class UserProfile(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user.first_name} Profile"
