from rest_framework.serializers import ModelSerializer, SerializerMethodField
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.templatetags.static import static

from .models import *

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        
        user = self.user
        if not user.is_verified:
            raise serializers.ValidationError('Email not verified. Please check your email for the verification link.')

        # Check if the user has a profile_picture before accessing it
        profile_picture = getattr(user, 'profile_picture', None)
        if profile_picture:
            data['profile_picture'] = static(profile_picture.url)

        return data

class UserSerializer(serializers.ModelSerializer):
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
        ]
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        password = validated_data.pop('password')

        user = super().create(validated_data)
        user.set_password(password)
        user.save()

        return user

    # def update(self, instance, validated_data):
    #     # Handle partial updates
    #     instance.first_name = validated_data.get('first_name', instance.first_name)
    #     instance.last_name = validated_data.get('last_name', instance.last_name)
    #     instance.email = validated_data.get('email', instance.email)
    #     instance.is_verified = validated_data.get('is_verified', instance.is_verified)
    #     instance.kyc_verified = validated_data.get('kyc_verified', instance.kyc_verified)
    #     instance.identification_type = validated_data.get('identification_type', instance.identification_type)
    #     instance.address_document_type = validated_data.get('address_document_type', instance.address_document_type)

    #     # Handle file uploads
    #     instance.identification_document = validated_data.get('identification_document', instance.identification_document)
    #     instance.address_document = validated_data.get('address_document', instance.address_document)

    #     instance.save()

    #     return instance

class ResendVerificationEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()