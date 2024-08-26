from accounts.api.v1.views import *
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView


app_name = 'api-v1'

urlpatterns = [
    # registration
    path('registration/', RegistrationAPIView.as_view(), name='registration'),
    path('confirm-registration/', ConfirmRegistrationView.as_view()),
    path("google-signup/", GoogleAuthRedirect.as_view()),
    path("google-signup-redirect/", GoogleRedirectURIView.as_view()),

    # change password
    path('change-password/', ChangePasswordApiView.as_view(), name='change-password'),
    
    # reset password
    path('forget_password/', PasswordResetRequestView.as_view(), name='forget_password'),
    
    # login token
    path('token/login/',CustomLoginView.as_view(), name='token-login'),
    path('token/logout/',CustomDiscardAuthToken.as_view(), name='token-logout'),

    # login jwt
    path('jwt/create/', CustomTokenObtainPairView.as_view(), name='jwt-create'),
    path('jwt/refresh/', TokenRefreshView.as_view(), name='jwt_refresh'),
    path('jwt/verify/', TokenVerifyView.as_view(), name='jwt_verify'),
    path('jwt/decode/', DecodeTokenView.as_view(), name='jwt-decode'),

    # profile
    path('profile/', ProfileApiView.as_view(), name='profile'),

    path('check-user-roll/', CheckUserRollView.as_view(), name='check-user-roll'),
]
