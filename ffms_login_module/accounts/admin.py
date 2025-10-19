from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    # Use email instead of username
    ordering = ('email',)
    list_display = ('email', 'first_name', 'last_name', 'role', 'department', 'is_active', 'email_verified')
    list_filter = ('role', 'department', 'is_active', 'email_verified')
    search_fields = ('email', 'first_name', 'last_name')
    
    # Fields for editing user
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('FFMS Information', {
            'fields': ('role', 'phone_number', 'department', 'student_id', 'faculty_id', 'email_verified', 'verification_token')
        }),
    )
    
    # Fields for creating user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'role'),
        }),
    )
    
    # Use email as username field
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        is_superuser = request.user.is_superuser
        disabled_fields = set()
        
        if not is_superuser:
            disabled_fields |= {
                'is_superuser',
                'user_permissions',
            }
        
        for field in disabled_fields:
            if field in form.base_fields:
                form.base_fields[field].disabled = True
        
        return form