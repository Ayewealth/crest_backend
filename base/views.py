import logging
from decimal import Decimal
from .utils import Util
from .serializers import *
from .models import *
from django.shortcuts import get_object_or_404, redirect
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework.permissions import IsAuthenticated
from django.core.mail import send_mail
import jwt
from django.conf import settings
from environ import Env
env = Env()
env.read_env()

logger = logging.getLogger(__name__)

# Create your views here.


@api_view(['Get'])
def endpoints(request):
    data = [
        '/signup',
        '/signin',
        '/token/refresh',
        '/users',
        '/users/:id',
        '/wallets',
        '/investment_sub'
    ]
    return Response(data)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


class UserCreateApiView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        if response.status_code == status.HTTP_201_CREATED:
            user_data = response.data
            user = CustomUser.objects.get(email=user_data['email'])

            refresh = RefreshToken.for_user(user)
            token = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }

            current_site = get_current_site(request).domain
            relative_link = reverse('email-verify')
            absurl = 'http://' + current_site + \
                relative_link + "?token=" + str(token['access'])
            email_body = 'Hi ' + user.first_name + \
                ' Use the link below to verify your email \n' + absurl
            email_data = {'email_body': email_body, 'to_email': user.email,
                          'email_subject': 'Verify your email'}

            Util.send_email(email_data)

        return response


class UserListApiView(generics.ListAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer


class UserRetrieveUpdateDestroyApiView(generics.RetrieveUpdateDestroyAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'pk'

    def patch(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()

        # Exclude 'password' from the request data
        fields_to_exclude = []

        # Include all other fields in the request data
        request_data = {
            key: value for key, value in request.data.items()
            if key not in fields_to_exclude
        }

        # Check if the image fields are provided in the request data
        if 'profile_picture' in request.data:
            profile_picture = request.FILES.get('profile_picture')
            if profile_picture:
                # Update the profile picture if provided
                request_data['profile_picture'] = profile_picture
            else:
                # Retain the existing profile picture
                request_data['profile_picture'] = instance.profile_picture

        # Similarly, check and update other image fields as needed
        if 'identification_document' in request.data:
            identification_document = request.FILES.get(
                'identification_document')
            if identification_document:
                request_data['identification_document'] = identification_document
            else:
                request_data['identification_document'] = instance.identification_document

        if 'address_document' in request.data:
            address_document = request.FILES.get('address_document')
            if address_document:
                request_data['address_document'] = address_document
            else:
                request_data['address_document'] = instance.address_document

        serializer = self.get_serializer(
            instance, data=request_data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


class VerificationMail(generics.GenericAPIView):
    def get(self, request):
        token = request.GET.get('token')
        try:
            secret_key = env('SECRET_KEY')
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            user = get_object_or_404(CustomUser, id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            redirect_url = "https://crest-rho.vercel.app/signin"
            return redirect(redirect_url)
        except jwt.ExpiredSignatureError as identifier:
            print("Expired Signature Error:", identifier)
            redirect_url = "https://crest-rho.vercel.app/confirmation-mail"
            return redirect(redirect_url)
            # return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            print("Decode Error:", identifier)
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            print("User not found")
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class ResendVerificationEmailView(generics.GenericAPIView):
    serializer_class = ResendVerificationEmailSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        user = CustomUser.objects.filter(email=email).first()

        if user:
            refresh = RefreshToken.for_user(user)
            token = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }

            current_site = get_current_site(request).domain
            relative_link = reverse('email-verify')
            absurl = 'http://' + current_site + \
                relative_link + "?token=" + str(token['access'])
            email_body = 'Hi ' + user.first_name + \
                ' Use the link below to verify your email \n' + absurl
            email_data = {'email_body': email_body, 'to_email': user.email,
                          'email_subject': 'Verify your email'}

            Util.send_email(email_data)

            return Response({'message': 'Verification email resent successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = CustomUser.objects.get(email=email)
        otp_record, created = PasswordResetOTP.objects.get_or_create(
            user=user, is_used=False)
        otp_record.generate_otp()

        send_mail(
            'Your Password Reset OTP',
            f'Your OTP for password reset is: {otp_record.otp}',
            'cresttradeworldwide@gmail.com',
            [email],
            fail_silently=False,
        )

        return Response({"message": "OTP sent to your email."}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)


class UserProfileListApiView(generics.ListAPIView):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer


class UserProfileRetriveUpdateDestroyApiView(generics.RetrieveUpdateDestroyAPIView):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    lookup_field = 'pk'


class WalletListApiView(generics.ListAPIView):
    queryset = Wallet.objects.all()
    serializer_class = WalletSerializer


class WalletRetriveUpdateDestroyApiView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Wallet.objects.all()
    serializer_class = WalletSerializer
    lookup_field = 'pk'

    def perform_update(self, serializer):
        wallet = self.get_object()
        old_balance = wallet.balance
        logger.debug(f"Old balance before update: {old_balance}")

        serializer.save()

        wallet.refresh_from_db()
        new_balance = wallet.balance
        logger.debug(f"New balance after update: {new_balance}")

        if old_balance != new_balance:
            user = wallet.user
            email_subject = 'Wallet Balance Update'
            email_body = f'Hi {user.first_name},\n\nYour wallet balance has been updated. New balance: {new_balance}.\n\nThank you.'
            to_email = user.email

            email_data = {
                'email_subject': email_subject,
                'email_body': email_body,
                'to_email': to_email
            }

            logger.debug(f"Sending email to {to_email}")

            Util.send_email(email_data)

    def update(self, request, *args, **kwargs):
        logger.debug("Update method called")
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        logger.debug(f"Instance before update: {instance}")
        serializer = self.get_serializer(
            instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        logger.debug("Serializer is valid, calling perform_update")
        self.perform_update(serializer)
        logger.debug("perform_update called successfully")
        return Response(serializer.data)


class InvestmentListCreateApiView(generics.ListCreateAPIView):
    queryset = Investment.objects.all()
    serializer_class = InvestmentSerializer


class InvestmentSubscriptionListCreateApiView(generics.ListCreateAPIView):
    queryset = InvestmentSubscription.objects.all()
    serializer_class = InvestmentSubscriptionSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        data = request.data
        wallet_id = data.get('wallet')
        investment_plan_id = data.get('investment_plan')
        amount = data.get('amount')

        try:
            wallet = Wallet.objects.get(id=wallet_id, user=request.user)
        except Wallet.DoesNotExist:
            return Response({"error": "Wallet does not exist or does not belong to the current user"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            investment_plan = Investment.objects.get(id=investment_plan_id)
        except Investment.DoesNotExist:
            return Response({"error": "Investment plan does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        amount_decimal = Decimal(amount)
        if wallet.balance < amount_decimal:
            return Response({"error": "Insufficient balance in the wallet"}, status=status.HTTP_400_BAD_REQUEST)

        wallet.balance -= amount_decimal
        wallet.save()

        investment_subscription_data = {
            'user': request.user.id,
            'wallet': wallet_id,
            'investment_plan': investment_plan_id,
            'amount': amount
        }
        serializer = self.get_serializer(data=investment_subscription_data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class TransactionListCreateApiView(generics.ListCreateAPIView):
    queryset = Transaction.objects.all()
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        data = request.data
        wallet_id = data.get('wallet')
        amount = data.get('amount')
        transaction_type = data.get('transaction_type')
        wallet_address = data.get('wallet_address')
        transaction_status = data.get('status')

        try:
            wallet = Wallet.objects.get(id=wallet_id, user=request.user)
        except Wallet.DoesNotExist:
            return Response({"error": "Wallet does not exist or does not belong to the current user"}, status=status.HTTP_400_BAD_REQUEST)

        amount_decimal = Decimal(amount)
        if amount_decimal <= Decimal(0):
            return Response({"error": "Transaction amount must be greater than zero"}, status=status.HTTP_400_BAD_REQUEST)

        if transaction_type == 'withdrawal' and wallet.balance < amount_decimal:
            return Response({"error": "Insufficient funds in the wallet"}, status=status.HTTP_400_BAD_REQUEST)

        if transaction_status == 'done' and transaction_type == 'deposit':
            wallet.balance += amount_decimal
            wallet.save()
        elif transaction_status == 'done' and transaction_type == 'withdrawal':
            wallet.balance -= amount_decimal
            wallet.save()

        if request.user.is_superuser:
            superusers = CustomUser.objects.filter(is_superuser=True)
            for superuser in superusers:
                email_body = 'Hi ' + request.user.full_name() + \
                    ' Just Made a request please go approve or decline request \n'
                email_data = {'email_body': email_body, 'to_email': superuser.email,
                              'email_subject': 'Transaction Mail'}

                Util.send_email(email_data)

        transaction_data = {
            'user': request.user.id,
            'wallet': wallet_id,
            'amount': amount_decimal,
            'status': transaction_status,
            'transaction_type': transaction_type,
            'wallet_address': wallet_address
        }
        serializer = self.get_serializer(data=transaction_data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class TransactionRetrieveUpdateDestroyApiView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Transaction.objects.all()
    serializer_class = TransactionSerializer
    lookup_field = "pk"

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(
            instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        old_status = instance.status
        new_status = request.data.get('status', old_status)

        if new_status != old_status:
            if new_status == 'done' and instance.transaction_type == 'deposit':
                wallet = instance.wallet
                amount = instance.amount
                wallet.balance += amount
                wallet.save()
            elif new_status == "done" and instance.transaction_type == "withdrawal":
                wallet = instance.wallet
                amount = instance.amount
                wallet.balance -= amount
                wallet.save()

        self.perform_update(serializer)
        return Response(serializer.data)
