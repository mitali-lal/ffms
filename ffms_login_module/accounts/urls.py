from django.urls import path
from . import views

urlpatterns = [
    # Web pages
    path('', views.login_page, name='login_page'),
    path('login/', views.login_page, name='login_page'),
    path('register/', views.register_page, name='register_page'),
    
    # API endpoints
    path('api/auth/register/', views.register_user, name='register_user'),
    path('api/auth/login/', views.user_login, name='user_login'),
    path('api/auth/logout/', views.user_logout, name='user_logout'),
    path('api/auth/profile/', views.user_profile, name='user_profile'),
    path('api/auth/verify-email/<uuid:token>/', views.verify_email, name='verify_email'),
    path('api/auth/resend-verification/', views.resend_verification, name='resend_verification'),
    path('forgot-password/', views.forgot_password_page, name='forgot_password_page'),
    path('api/auth/forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<uuid:token>/', views.reset_password_page, name='reset_password_page'),
    path('api/auth/reset-password/<uuid:token>/', views.reset_password, name='reset_password'),
    path('api/auth/change-password/', views.change_password, name='change_password'),
]