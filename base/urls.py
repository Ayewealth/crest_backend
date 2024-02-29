from django.urls import path

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from . import views

urlpatterns = [
    path('', views.endpoints),

    path('signup', views.UserListCreateApiView.as_view(), name='signup'),
    path('signup/<str:pk>/', views.UserRetrieveUpdateDestroyApiView.as_view(), name='user'),
    path('email-verify/', views.VerificationMail.as_view(), name="email-verify"),
    path('resend-email-verification', views.ResendVerificationEmailView.as_view(), name="resend-email-verification"),

    path('signin/', views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]