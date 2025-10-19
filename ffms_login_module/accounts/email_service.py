from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def send_verification_email(user):
    verification_url = f"{settings.SITE_URL}/api/auth/verify-email/{user.verification_token}/"
    
    html_message = render_to_string('accounts/verification_email.html', {
        'user': user,
        'verification_url': verification_url,
    })
    
    plain_message = strip_tags(html_message)
    
    send_mail(
        'Verify Your FFMS Account',
        plain_message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        html_message=html_message,
        fail_silently=False,
    )

def send_password_reset_email(user, reset_token):
    reset_url = f"{settings.SITE_URL}/reset-password/{reset_token}/"
    
    html_message = render_to_string('accounts/password_reset_email.html', {
        'user': user,
        'reset_url': reset_url,
    })
    
    plain_message = strip_tags(html_message)
    
    send_mail(
        'Reset Your FFMS Password',
        plain_message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        html_message=html_message,
        fail_silently=False,
    )