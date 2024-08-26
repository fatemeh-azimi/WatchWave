from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from easy_select2 import Select2
from .models import User, Profile  # Import your models

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ('id', 'username', 'is_superuser', 'is_supervisor', 'is_staff', 'is_verified', 'created_date', 'last_login')
    list_filter = ('username', 'is_superuser', 'is_supervisor', 'is_staff', 'is_verified', 'created_date', 'last_login')
    search_fields = ('username', )
    date_hierarchy = 'created_date'
    ordering = ('username', )
    fieldsets = (
        ('Authentication', {
            "fields": (
                    'username', 'password'
            ), 
        }), 
        ('permissions', {
            "fields": ('is_superuser', 'is_supervisor', 'is_staff', 'is_verified'), 
        }), 
        ('group permissions', {
            "fields": ('groups', 'user_permissions'), 
        }), 
        ('important date', {
            "fields": ('last_login',), 
        }), 
    )
    add_fieldsets = (
         (None, {
            "classes": ('wide', ), 
            "fields": ('username', 'password1', 'password2', 'is_superuser', 'is_supervisor', 'is_staff',), 
        }), 
    )
admin.site.register(User, CustomUserAdmin)


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'last_name', 'first_name', 'created_date', 'updated_date')
    search_fields = ('first_name', 'last_name')
    readonly_fields = ('created_date', 'updated_date')
    fieldsets = (
        ('اطلاعات شخصی', {'fields': ('first_name', 'last_name')}),
        ('تاریخچه', {'fields': ('created_date', 'updated_date')}),
    )

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        if db_field.name == 'user':
            kwargs['widget'] = Select2()
        return super().formfield_for_dbfield(db_field, request, **kwargs)

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # If the user is a superuser, show all profiles
        if request.user.is_superuser:
            return qs
        # Otherwise, restrict to the user's own profile
        return qs.filter(user=request.user)