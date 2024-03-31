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
        '/token/refresh'
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
