import string, redis, secrets, hashlib, secrets, string, requests, logging
from logging import getLogger
from accounts.models import User, Profile
from accounts.api.v1.utils import log_user_action
from accounts.api.v1.serializers import *
from accounts.api.v1.utils import JWTUtility
#from channels.models import VideoPost
from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth import authenticate, login, get_user_model
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User  # Assuming you use the default User model
from django.core.mail import send_mail, BadHeaderError
from django.conf import settings
from django.views.generic.base import View
from django.utils.decorators import method_decorator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework_simplejwt.views import TokenObtainPairView


redis_cli = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
logger = getLogger(__name__)  # Get logger for the current module

def send_confirmation_email(username, code):    
    # Send email based on recipient type (modify for SMS)
    subject = 'Account Verification'
    message = f'Your verification code is: {code}'
    email_from = 'news@live.rasekhoon.net'
    send_mail(subject, message, email_from, [username], fail_silently=False)

def send_confirmation_sms(phones_number, template_id, parameters):
    url = "https://api.sms.ir/v1/send/verify"
    payload = {"mobile": phones_number, "templateId": template_id, "parameters": parameters}
    headers = {'Content-Type':'application/json', 'Accept':'text/plain', 'x-api-key':'*** Your Password ***'}
    response = requests.post(url, headers=headers, json=payload).json()
    # print(response["data"]["messageId"])

def generate_random_code(username, length=6):
  """Generates a random numeric code of the specified length."""
  expire_time = 108000
  chars = string.digits
  code = ''.join(secrets.choice(chars) for _ in range(length))
  hashed_code = hashlib.sha256(code.encode('utf-8')).hexdigest()  # Truncate to desired length
  # Check if code already exists for the user
  if not redis_cli.exists(username):
    redis_cli.set(username, value=hashed_code, ex=expire_time)  # Set code in Redis with expiration time
  else:
      redis_cli.delete(username)
      redis_cli.set(username, value=hashed_code, ex=expire_time)
  return code

def send_reset_password_email(username, code):    
    # Send email based on recipient type (modify for SMS)
    subject = 'Reset Password'
    message = f'Your verification code is: {code}'
    email_from = 'reset-password@live.rasekhoon.net '
    send_mail(subject, message, email_from, [username], fail_silently=False)

def send_reset_password_sms(phones_number, template_id, parameters):
    url = "https://api.sms.ir/v1/send/verify"
    payload = {"mobile": phones_number, "templateId": template_id, "parameters": parameters}
    headers = {'Content-Type':'application/json', 'Accept':'text/plain', 'x-api-key':'*** Your Password ***'}
    response = requests.post(url, headers=headers, json=payload).json()
    # print(response["data"]["messageId"])

class RegistrationAPIView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = RegistrationSerializer
    def post(self, request, format=None):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.set_password(serializer.validated_data['password'])
            user.save()
            # Log successful registration
            log_user_action(user, 'registered')
            return Response({'message': 'Registration successful! Please verify your account.'}, status=status.HTTP_201_CREATED)
        else:
            # Log failed registration
            log_user_action(None, 'failed_registration', serializer.errors)
            logger.error(f"Registration failed {serializer.errors}")
            # Consider deleting the created user object or rolling back changes
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ConfirmRegistrationView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ConfirmRegistrationSerializer

    def get(self, request, *args, **kwargs):
        user = request.user
        if user.is_verified:
            return Response({'message': 'Account is already active.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            try:
                # Confirmation logic (assuming `ConfirmationCode` model exists)
                code = generate_random_code(user.username)
                logger.info(f"Confirmation code created for user {user.username}")

                # Send confirmation based on provided field
                if '@' in user.username:
                    send_confirmation_email(user.username, code)
                    logger.info(f"Confirmation email sent to {user.username}")
                else:
                    parameters = [{"name": "USERNAME", "value": user.username}, {"name": "CODE", "value": code}]
                    send_confirmation_sms(user.username, 633907, parameters)  # Modify for SMS
                    logger.info(f"Confirmation SMS sent to {user.username}")
                return Response({'message': 'Confirmation code sent.'}, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error(f"Error during confirmation request: {str(e)}")
                return Response({'error': f'An error occurred during confirmation. \n{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request, *args, **kwargs):
        user = request.user
        if not user.is_verified:
            try:
                serializer = self.get_serializer(data=request.data, context={'user': user})
                serializer.is_valid(raise_exception=True)

                log_user_action(user, 'confirmed_account', request.data.get('code'))  # Log confirmation action

                return Response({'message': 'Account confirmed successfully!'}, status=status.HTTP_200_OK)
            except Exception as e:
                log_user_action(user, 'failed_confirmation_attempt', request.data.get('code'))  # Log failed attempt
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'message': 'Account already confirmed!'}, status=status.HTTP_200_OK)


class CustomDiscardAuthToken(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        try:
            # Delete user's token
            # Token.objects.filter(user=user).delete()  # Delete all tokens for the user
            request.user.auth_token.delete()

            # Log token discard
            logger.info(f"User {user.username} discarded their authentication token (user_id: {user.pk})")

            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            # Log error during token discard
            logger.error(f"Error discarding token for user {user.username} (user_id: {user.pk}). (error: {str(e)})")
            return Response({'error': 'An error occurred while discarding the token.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request):
        user = request.user
        user.is_verified = False
        user.save()

        # Log user unverification
        logger.info(f"User {user.username} unverified their account. (user_id: {user.pk})")

        return Response(status=status.HTTP_200_OK)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = TokenObtainPairSerializer


class ProfileApiView(generics.RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    queryset = Profile.objects.all()
    permission_classes = [IsAuthenticated]

    def get_object(self):
        queryset = self.get_queryset()
        obj = get_object_or_404(queryset, user=self.request.user)
        return obj
    
    #def my_posts(self):
    #    my_posts = VideoPost.objects.filter(publisher = self.request.user)
    #    return my_posts


class ChangePasswordApiView(generics.GenericAPIView):
    model = User
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerialier
    
    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST,)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            # Log password change
            log_user_action(self.object, 'changed_password')
            return Response({"details": "password changed successfully"}, status=status.HTTP_200_OK,)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def get(self, request, *args, **kwargs):
        user = request.user
        try:
            # Confirmation logic (assuming `ConfirmationCode` model exists)
            code = generate_random_code(user.username)
            logger.info(f"reset password code created for user {user.username}")

            # Send confirmation based on provided field
            if '@' in user.username:
                send_reset_password_email(user.username, code)
                logger.info(f"reset password email sent to {user.username}")
            else:
                parameters = [{"name": "USERNAME", "value": user.username}, {"name": "CODE", "value": code}]
                send_reset_password_sms(user.username, 154985, parameters)  # Modify for SMS
                logger.info(f"reset password SMS sent to {user.username}")
            return Response({'message': 'reset password code sent.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error during reset password request: {str(e)}")
            return Response({'error': f'An error occurred during reset password. \n{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request, *args, **kwargs):
        user = request.user
        try:
                serializer = self.get_serializer(data=request.data, context={'user': user})
                serializer.is_valid(raise_exception=True)

                log_user_action(user, 'reset password', request.data.get('code'))  # Log confirmation action

                return Response({'message': 'Password reset successfully!'}, status=status.HTTP_200_OK)
        except Exception as e:
                log_user_action(user, 'failed_reset_password_attempt', request.data.get('code'))  # Log failed attempt
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

@method_decorator(csrf_exempt, name='dispatch')
class CustomLoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        response = Response()
        response['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response['Access-Control-Allow-Methods'] = 'POST'
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'

        serializer = self.get_serializer(data=request.data)
        # serializer = self.serializer_class(data=request.data,
        #                                    context={'request': request})
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        try:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                User = get_user_model()
                user = User.objects.get(username=username)
                token, created = Token.objects.get_or_create(user=user)
                is_superuser = user.is_superuser
                is_supervisor = user.is_supervisor
                is_staff = user.is_staff
                if is_superuser and is_supervisor and is_staff:
                    role = 'is_superuser'
                elif not is_superuser and is_supervisor and is_staff:
                    role = 'is_supervisor'
                elif not is_superuser and not is_supervisor and is_staff:
                    role = 'staff'
                else:
                    role = 'nobody'
        
                response.data = {
                    'message': 'Login successful',
                    'token': token.key,
                    'user_id': user.pk,
                    'username': username,
                    'role': role
                }
                response.status_code = status.HTTP_200_OK
                 # Log successful login
                logger.info(f"User {username} logged in successfully. (user_id: {user.pk}, role: {role})")
            else:
                response.data = {'error': 'Invalid username or password'}
                response.status_code = status.HTTP_401_UNAUTHORIZED
                # Log failed login attempt
                logger.warning(f"Failed login attempt for username: {username}")
        except ValidationError as e:
            if 'username' in e.message_dict:
                response.data = {'error': 'Invalid username'}
                response.status_code = status.HTTP_400_BAD_REQUEST
            elif 'password' in e.message_dict:
                response.data = {'error': 'Incorrect password'}
                response.status_code = status.HTTP_400_BAD_REQUEST
            else:
                response.data = {'error': 'User does not exist'}
                response.status_code = status.HTTP_400_BAD_REQUEST
            # Log error during login
            logger.error(f"Error during login for username: {username} (error: {str(e)})")
        return response
  

class GoogleAuthRedirect(View):
    permission_classes = [AllowAny]
    
    def get(self, request):
        redirect_url = f"https://accounts.google.com/o/oauth2/v2/auth?client_id={settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY}&response_type=code&scope=https://www.googleapis.com/auth/userinfo.profile%20https://www.googleapis.com/auth/userinfo.email&access_type=offline&redirect_uri=http://127.0.0.1:8000/accounts/api/v1/google-signup-redirect/"
        return redirect(redirect_url)
    

class GoogleRedirectURIView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        # Extract the authorization code from the request URL
        code = request.GET.get('code')
        
        if code:
            # Prepare the request parameters to exchange the authorization code for an access token
            token_endpoint = 'https://oauth2.googleapis.com/token'
            token_params = {
                'code': code,
                'client_id': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
                'client_secret': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
                'redirect_uri': 'http://127.0.0.1:8000/accounts/api/v1/google-signup-redirect/',  # Must match the callback URL configured in your Google API credentials
                'grant_type': 'authorization_code',
            }
            
            # Make a POST request to exchange the authorization code for an access token
            response = requests.post(token_endpoint, data=token_params)

            if response.status_code == 200:
                access_token = response.json().get('access_token')
                
                if access_token:
                    # Make a request to fetch the user's profile information
                    profile_endpoint = 'https://www.googleapis.com/oauth2/v1/userinfo'
                    headers = {'Authorization': f'Bearer {access_token}'}
                    profile_response = requests.get(profile_endpoint, headers=headers)
                    
                    if profile_response.status_code == 200:
                        data = {}
                        profile_data = profile_response.json()
                        # Proceed with user creation or login
                        user = User.objects.create_user(
                                username=profile_data["email"],
                                password='  '
                                # first_name=profile_data["given_name"],
                                # email=profile_data["email"]
                                )
                        # if "family_name" in profile_data:
                        #     user.last_name = profile_data["family_name"]
                        #     user.save
                        # refresh = RefreshToken.for_user(user)
                        # data['access'] = str(refresh.access_token)
                        # data['refresh'] = str(refresh)
                        return Response(data, status.HTTP_201_CREATED)
        
        return Response({}, status.HTTP_400_BAD_REQUEST)        


class CheckUserRollView(generics.GenericAPIView):
    ''' 
    This view determines the user's role (superuser, supervisor, staff or nobody).
        Success and failure scenarios are logged accordingly.
    '''
    serializer_class = CheckUserRollSerializer
    def post(self, request):
        response = Response()

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        try:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                User = get_user_model()
                user = User.objects.get(username=username)
                is_superuser = user.is_superuser
                is_supervisor = user.is_supervisor
                is_staff = user.is_staff
                if is_superuser and is_supervisor and is_staff:
                    role = 'is_superuser'
                elif not is_superuser and is_supervisor and is_staff:
                    role = 'is_supervisor'
                elif not is_superuser and not is_supervisor and is_staff:
                    role = 'staff'
                else:
                    role = 'nobody'
                response.data = {
                    'message': 'Determined user role',
                    'role': role
                }
                response.status_code = status.HTTP_200_OK
                 # Log successful login
                logger.info(f"User {username} Determined successfully. (user_id: {user.pk}, role: {role})")
            else:
                response.data = {'error': 'Invalid username or password'}
                response.status_code = status.HTTP_401_UNAUTHORIZED
                # Log failed login attempt
                logger.warning(f"Failed login attempt for username: {username}")
        except ValidationError as e:
            if 'username' in e.message_dict:
                response.data = {'error': 'Invalid username'}
                response.status_code = status.HTTP_400_BAD_REQUEST
            elif 'password' in e.message_dict:
                response.data = {'error': 'Incorrect password'}
                response.status_code = status.HTTP_400_BAD_REQUEST
            else:
                response.data = {'error': 'User does not exist'}
                response.status_code = status.HTTP_400_BAD_REQUEST
            # Log error during login
            logger.error(f"Error during login for username: {username} (error: {str(e)})")
        return response
    

class DecodeTokenView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = TokenSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            
            decoded_payload = JWTUtility.decode_jwt_token(token)

            if decoded_payload is None:
                return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

            return Response({'decoded_payload': decoded_payload})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    