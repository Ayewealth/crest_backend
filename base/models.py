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
    profile_picture = models.ImageField(upload_to='profile_pics', blank=True, null=True)

    # User Detail fields
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    email = models.EmailField(unique=True)

    # Kyc related fields 
    identification_type = models.CharField(max_length=50, blank=True, choices=[("national_id", "National ID"), ("passport", "International Passport")])
    identification_document = models.ImageField(upload_to='kyc', blank=True,null=True)
    address_document_type = models.CharField(max_length=50, blank=True, choices=[("utility_bill", "Utility Bill"), ("bank_reference", "Bank Reference"), ("proof_of_residence", "Proof of Residence"), ("permit", "Driver or Residence Permit")])
    address_document = models.ImageField(upload_to='kyc', blank=True, null=True)


    is_verified = models.BooleanField(default=False)
    kyc_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email