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

        if user.profile_picture:
            data['profile_picture'] = static(user.profile_picture.url)

        return data

class UserSerializer(ModelSerializer):
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
            'identification_type',
            'identification_document',
            'address_document_type',
            'address_document',
        ]

    def create(self, validated_data):
        password = validated_data.pop('password')

        user = super().create(validated_data)
        user.set_password(password)
        user.save()

        return user

class ResendVerificationEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()