import re, redis, hashlib
from accounts.models import User, Profile
from django.core import exceptions
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers


redis_cli = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)


class RegistrationSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True, required=True )

    class Meta:
        model = User
        fields = ('username', 'password', 'confirm_password')
        extra_kwargs = {
            'password': {
                'write_only': True,
                # 'style': {'input_type': 'password'}
                },
        }

    def validate_username(self, username):
        """
        Validates if the username is either a valid phone number or a valid email address.
        """
        phone_number_pattern = r'^09\d{9}$'  # Regular expression pattern for phone numbers (11 digits)
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Improved email pattern

        # Check if username matches phone number format
        if re.match(phone_number_pattern, username):
            return username  # Valid phone number

        # Check if username matches email format
        elif re.match(email_pattern, username):
            return username  # Valid email address

        # If not a valid phone number or email, raise an error
        raise serializers.ValidationError('Username must be either a valid phone number (starting with 09 and 11 digits)or a valid email address.')
        
        # You can remove the return statement at the end as it's unreachable
        # due to the raised exception if neither format matches.
            
    def validate(self, data):
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError('Passwords do not match.')

        return data

    
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password']
        )
        return user

class ConfirmRegistrationSerializer(serializers.Serializer):
    code = serializers.CharField(required=True)

    def validate_code(self, code):
        user = self.context.get('user')  # Access user object from context

        # Validate code presence and user validity
        if not code:
            raise serializers.ValidationError('Code is required.')
        if not user:
            raise serializers.ValidationError('Invalid user.')

        # Retrieve confirmation code from Redis
        stored_code = redis_cli.get(user.username)

        # Hash the entered code for comparison
        entered_code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()

        # Validate code match and expiration
        if not stored_code:
            raise serializers.ValidationError('Confirmation code not found.')
        if str(stored_code) != str(entered_code_hash):
            raise serializers.ValidationError('Invalid confirmation code.')

        # Mark user as verified
        user.is_verified = True
        user.save()

        return code  # Return validated code
    

User = get_user_model()

class PasswordResetRequestSerializer(serializers.Serializer):
    code = serializers.CharField(required=True)
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = self.context.get('user')  # Access user object from context

        # Validate code presence and user validity
        if not data['code']:
            raise serializers.ValidationError('Code is required.')
        if not user:
            raise serializers.ValidationError('Invalid user.')

        # Retrieve confirmation code from Redis
        stored_code = redis_cli.get(user.username)

        # Hash the entered code for comparison
        entered_code_hash = hashlib.sha256(data['code'].encode('utf-8')).hexdigest()

        # Validate code match and expiration
        if not stored_code:
            raise serializers.ValidationError('Confirmation code not found.')
        if str(stored_code) != str(entered_code_hash):
            raise serializers.ValidationError('Invalid confirmation code.')

        # Mark user as verified
        user.set_password(data['new_password'])
        user.save()
        return data  # Return validated code


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    uidb64 = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        try:
            uid = force_str(urlsafe_base64_decode(data['uidb64']))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError('Invalid token or user ID')
        
        if not PasswordResetTokenGenerator().check_token(user, data['token']):
            raise serializers.ValidationError('Invalid token or user ID')

        return data

    def save(self, validated_data):
        uid = force_str(urlsafe_base64_decode(validated_data['uidb64']))
        user = User.objects.get(pk=uid)
        user.set_password(validated_data['new_password'])
        user.save()
        return user
    

class TokenObtainPairSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(self, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        if user.is_superuser and user.is_supervisor and user.is_staff:
            role = 'is_superuser'
        elif not user.is_superuser and user.is_supervisor and user.is_staff:
            role = 'is_supervisor'
        elif not user.is_superuser and not user.is_supervisor and user.is_staff :
            role = 'staff'
        else :
            role = 'nobody'
        token['role'] = role

        if user.is_verified:
            token['verified'] = True
        else:
            token['verified'] = False

        return token
    
    def validate(self, attrs):
        validated_data = super().validate(attrs)
        validated_data['user_id'] = self.user.id
        validated_data['username'] = self.user.username
        if self.user.is_superuser and self.user.is_supervisor and self.user.is_staff:
            role = 'is_superuser'
        elif not self.user.is_superuser and self.user.is_supervisor and self.user.is_staff:
            role = 'is_supervisor'
        elif not self.user.is_superuser and not self.user.is_supervisor and self.user.is_staff :
            role = 'staff'
        else :
            role = 'nobody'
        validated_data['role']= role
        validated_data['message']= 'Login successful'
        
        if self.user.is_verified:
            validated_data['verified'] = True
        else:
            validated_data['verified'] = False
            
        return validated_data

class ProfileSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Profile
        fields = ['id', 'user', 'first_name', 'last_name', 'image', 'description', 'sex',
                'province', 'city', 'job', 'education', 'created_date', 'updated_date']

class ChangePasswordSerialier(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password1 = serializers.CharField(required=True)
    
    def validate(self, attrs):
        if attrs.get('new_password') != attrs.get('new_password1'):
            raise serializers.ValidationError({'detail': 'passswords doesnt match'})
        try:
            validate_password(attrs.get('new_password'))
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({'new_password': list(e.messages)})
        return super().validate(attrs)
    
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(
        label=_("username"),
        write_only=True
    )
    password = serializers.CharField(
        label=_("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )
    token = serializers.CharField(
        label=_("Token"),
        read_only=True
    )
    
class ObtainTokenSerializer(serializers.Serializer):
    token =serializers.CharField(max_length=128 , allow_null=False)
    refresh =serializers.CharField(max_length=128 , allow_null=False)
    created = serializers.BooleanField()



class CheckUserRollSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


# serializers.py
from rest_framework import serializers

class TokenSerializer(serializers.Serializer):
    token = serializers.CharField()