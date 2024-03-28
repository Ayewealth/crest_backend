from rest_framework.serializers import ModelSerializer, SerializerMethodField
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.templatetags.static import static
from django.utils.dateformat import DateFormat

from .models import *


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        user = self.user
        if not user.is_verified:
            raise serializers.ValidationError(
                'Email not verified. Please check your email for the verification link.')

        # Check if the user has a profile_picture before accessing it
        profile_picture = getattr(user, 'profile_picture', None)
        if profile_picture:
            data['profile_picture'] = profile_picture.url

        data['kyc_verified'] = user.kyc_verified

        return data


class UserSerializer(serializers.ModelSerializer):
    date_joined_formatted = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = [
            'id',
            'profile_picture',
            'first_name',
            'last_name',
            'email',
            'password',
            'is_verified',
            'kyc_verified',
            'identification_type',
            'identification_document',
            'address_document_type',
            'address_document',
            'date_joined',
            'date_joined_formatted'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'profile_picture': {'allow_null': True},
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)

        user = super().create(validated_data)

        if password:
            user.set_password(password)
            user.save()

        return user

    def get_date_joined_formatted(self, obj):
        # Format the date_joined field as "June 22, 2020"
        return DateFormat(obj.date_joined).format('F j, Y')


class ResendVerificationEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
