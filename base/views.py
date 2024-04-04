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


class InvestmentSubscriptionListCreateApiView(generics.ListCreateAPIView):
    queryset = InvestmentSubscription.objects.all()
    serializer_class = InvestmentSubscriptionSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        data = request.data
        wallet_id = data.get('wallet')
        investment_plan_id = data.get('investment_plan')
        amount = data.get('amount')

        # Check if wallet exists and belongs to the current user
        try:
            wallet = Wallet.objects.get(id=wallet_id, user=request.user)
        except Wallet.DoesNotExist:
            return Response({"error": "Wallet does not exist or does not belong to the current user"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if investment plan exists
        try:
            investment_plan = Investment.objects.get(id=investment_plan_id)
        except Investment.DoesNotExist:
            return Response({"error": "Investment plan does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        amount_decimal = Decimal(amount)
        # Check if the wallet has sufficient balance
        if wallet.balance < amount_decimal:
            return Response({"error": "Insufficient balance in the wallet"}, status=status.HTTP_400_BAD_REQUEST)

        # Deduct the amount from the wallet balance
        wallet.balance -= amount_decimal
        wallet.save()

        # Create the investment subscription
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
        transaction_status = data.get('status')

        # Check if wallet exists and belongs to the current user
        try:
            wallet = Wallet.objects.get(id=wallet_id, user=request.user)
        except Wallet.DoesNotExist:
            return Response({"error": "Wallet does not exist or does not belong to the current user"}, status=status.HTTP_400_BAD_REQUEST)

        amount_decimal = Decimal(amount)
        # Check if the transaction amount is greater than zero
        if amount_decimal <= Decimal(0):
            return Response({"error": "Transaction amount must be greater than zero"}, status=status.HTTP_400_BAD_REQUEST)

        # Update wallet balance based on transaction type and status
        if transaction_status == 'done' and transaction_type == 'deposit':
            print("Before balance update:", wallet.balance)
            wallet.balance += amount_decimal
            wallet.save()
            print("After balance update:", wallet.balance)

        if request.user.is_superuser:
            superusers = CustomUser.objects.filter(is_superuser=True)
            for superuser in superusers:
                email_body = 'Hi ' + request.user.full_name() + \
                    ' Just Made a request please go approve or decline request \n'
                email_data = {'email_body': email_body, 'to_email': superuser.email,
                              'email_subject': 'Admin Mail'}

                Util.send_email(email_data)

        # Create the transaction with pending status
        transaction_data = {
            'user': request.user.id,
            'wallet': wallet_id,
            'amount': amount_decimal,
            'status': transaction_status,
            'transaction_type': transaction_type
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

        # Check if the status is being updated
        old_status = instance.status
        new_status = request.data.get('status', old_status)

        if new_status != old_status:
            # If status is being updated, check if it's changing to "done"
            if new_status == 'done' and instance.transaction_type == 'deposit':
                # Update the wallet balance if the transaction is a deposit and status is becoming "done"
                wallet = instance.wallet
                amount = instance.amount
                print("Before balance update:", wallet.balance)
                wallet.balance += amount
                wallet.save()
                print("After balance update:", wallet.balance)
            elif new_status == "done" and instance.transaction_type == "withdrawal":
                wallet = instance.wallet
                amount = instance.amount
                print("Before balance update:", wallet.balance)
                wallet.balance -= amount
                wallet.save()
                print("After balance update:", wallet.balance)

        self.perform_update(serializer)
        return Response(serializer.data)
