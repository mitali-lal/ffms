from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import login, logout
from .models import User
from .serializers import EmailLoginSerializer, UserSerializer, UserRegistrationSerializer
from .email_service import send_verification_email
import uuid
from django.conf import settings
from django.core.mail import send_mail

# Template views
def login_page(request):
    if request.user.is_authenticated:
        return redirect('/dashboard/')
    return render(request, 'accounts/login.html')

def register_page(request):
    if request.user.is_authenticated:
        return redirect('/dashboard/')
    return render(request, 'accounts/register.html')

def forgot_password_page(request):
    return render(request, 'accounts/forgot_password.html')
def reset_password_page(request, token):
    """Display reset password form"""
    try:
        user = User.objects.get(verification_token=token)
        return render(request, 'accounts/reset_password.html', {'token': token, 'valid': True})
    except User.DoesNotExist:
        return render(request, 'accounts/reset_password.html', {'valid': False})

def dashboard(request):
    # MANUAL SECURITY CHECK
    if not request.user.is_authenticated:
        print("SECURITY BREACH: Anonymous user trying to access dashboard!")
        return redirect('/?error=not_logged_in')
    
    print(f"User {request.user.username} accessed dashboard")
    
    user = request.user
    if user.role == 'student':
        return render(request, 'dashboard/student.html')
    elif user.role == 'faculty':
        return render(request, 'dashboard/faculty.html')
    elif user.role == 'admin':
        return render(request, 'dashboard/admin.html')
    else:
        return render(request, 'dashboard/base.html')

# API views
@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    """Handle new user registration with email verification"""
    try:
        serializer = UserRegistrationSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            
            # Send verification email
            try:
                send_verification_email(user)
                return Response({
                    'message': 'Registration successful! Please check your email for verification link.',
                    'user_id': user.id
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                # If email fails, delete the user and return error
                user.delete()
                return Response({
                    'error': 'Failed to send verification email. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        return Response({
            'error': 'Registration failed. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def user_login(request):
    """Handle user login with comprehensive error messages"""
    try:
        serializer = EmailLoginSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            login(request, user)
            
            return Response({
                'message': 'Login successful!',
                'user': UserSerializer(user).data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        return Response({
            'error': 'Login failed due to server error. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# In views.py - FIX THE LOGOUT
@api_view(['POST'])
@permission_classes([IsAuthenticated]) 
def user_logout(request):
    logout(request)
    request.session.flush()  # Clear session completely
    return Response({
        'message': 'Logout successful',
        'redirect_url': '/login/'  # ← ADD THIS REDIRECT!
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(request, token):
    """Handle email verification link"""
    try:
        user = User.objects.get(verification_token=token)
        
        if user.email_verified:
            return Response({
                'message': 'Email already verified. You can now login.'
            }, status=status.HTTP_200_OK)
        
        user.email_verified = True
        user.save()
        
        return Response({
            'message': 'Email verified successfully! You can now login to your account.'
        }, status=status.HTTP_200_OK)
        
    except User.DoesNotExist:
        return Response({
            'error': 'Invalid verification link. Please request a new verification email.'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'error': 'Verification failed. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def resend_verification(request):
    """Resend verification email"""
    try:
        email = request.data.get('email')
        
        if not email:
            return Response({
                'error': 'Email address is required.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            
            if user.email_verified:
                return Response({
                    'message': 'Email already verified. You can login now.'
                }, status=status.HTTP_200_OK)
            
            # Generate new verification token
            user.verification_token = uuid.uuid4()
            user.save()
            
            send_verification_email(user)
            
            return Response({
                'message': 'Verification email sent! Please check your inbox.'
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({
                'error': 'No account found with this email. Please register first.'
            }, status=status.HTTP_404_NOT_FOUND)
            
    except Exception as e:
        return Response({
            'error': 'Failed to send verification email. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password(request):
    """Send password reset email"""
    print("=== DEBUG: Forgot password endpoint called ===") 
    try:
        email = request.data.get('email')
        
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
            print(f"=== DEBUG: Email received: {email}") 
        
        # Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'No account found with this email'}, status=status.HTTP_404_NOT_FOUND)
        
        # Generate reset token
        reset_token = uuid.uuid4()
        user.verification_token = reset_token  # Reuse the same field for simplicity
        user.save()
        
        # Send reset email
        reset_url = f"{settings.SITE_URL}/reset-password/{reset_token}/"
        
        # Simple email for now
        send_mail(
            'Reset Your FFMS Password',
            f'Click this link to reset your password: {reset_url}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        
        return Response({'message': 'Password reset link sent to your email'}, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"=== DEBUG: Error occurred: {e}")
        return Response({'error': 'Failed to process request'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request, token):
    """Handle password reset"""
    try:
        new_password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')
        
        if not new_password or not confirm_password:
            return Response({'error': 'Both password fields are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if new_password != confirm_password:
            return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Find user by token
        try:
            user = User.objects.get(verification_token=token)
        except User.DoesNotExist:
            return Response({'error': 'Invalid or expired reset link'}, status=status.HTTP_404_NOT_FOUND)

        # === SECURITY FIX: KILL ALL SESSIONS BEFORE password change ===
        from django.contrib.sessions.models import Session
        from django.utils import timezone
        
        # Delete all active sessions for this user
        sessions = Session.objects.filter(expire_date__gte=timezone.now())
        for session in sessions:
            session_data = session.get_decoded()
            if session_data.get('_auth_user_id') == str(user.id):
                session.delete()
        
        # Set new password
        user.set_password(new_password)
        user.verification_token = uuid.uuid4()  # Generate new token for security
        user.save()
        
        return Response({'message': 'Password reset successful! You can now login with your new password.'}, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({'error': 'Failed to reset password'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # ADD THIS NEW VIEW - For logged-in users to change password
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # Only logged-in users
def change_password(request):
    """Change password while logged in - WITH SECURITY"""
    try:
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        
        # Validation
        if not current_password or not new_password or not confirm_password:
            return Response({
                'error': 'All password fields are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if new_password != confirm_password:
            return Response({
                'error': 'New passwords do not match'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify current password
        if not request.user.check_password(current_password):
            return Response({
                'error': 'Current password is incorrect'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # === SECURITY FIX: KILL ALL SESSIONS ===
        from django.contrib.sessions.models import Session
        from django.utils import timezone
        
        sessions = Session.objects.filter(expire_date__gte=timezone.now())
        for session in sessions:
            session_data = session.get_decoded()
            if session_data.get('_auth_user_id') == str(request.user.id):
                session.delete()
        
        # Set new password
        request.user.set_password(new_password)
        request.user.save()
        
        # Logout current session
        logout(request)
        
        return Response({
            'message': 'Password changed successfully! Please login again with your new password.',
            'redirect_url': '/login/'
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': 'Failed to change password'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)