from rest_framework import serializers
from django.contrib.auth import authenticate
from django.db import IntegrityError
from .models import User

class EmailLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')

        if email and password:
            user = authenticate(email=email, password=password)
            if user:
                if not user.email_verified:
                    raise serializers.ValidationError('Email not verified. Please check your inbox.')
                if user.role != role:
                    raise serializers.ValidationError('Invalid role for this user.')
                data['user'] = user
            else:
                raise serializers.ValidationError('Unable to log in with provided credentials.')
        return data

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'password_confirm', 'role', 'first_name', 'last_name', 'phone_number', 'department')

    def validate_email(self, value):
        # TEMPORARY FOR TESTING: Allow any email
        if '@' not in value:
            raise serializers.ValidationError('Please enter a valid email address.')
        
        if User.objects.filter(email=value).exists():
            user = User.objects.get(email=value)
            if user.email_verified:
                raise serializers.ValidationError('This email is already registered. Please login instead.')
            else:
                raise serializers.ValidationError('This email is pending verification. Please check your inbox.')
        
        return value

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        user.email_verified = False
        user.save()
        return user

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'role', 'first_name', 'last_name', 'phone_number', 'department', 'email_verified')