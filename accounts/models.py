from django.db import models
from django.contrib.auth.models import (BaseUserManager, AbstractBaseUser, PermissionsMixin)
from django.utils.translation import gettext_lazy as _
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django_jalali.db import models as jmodels
#from django.utils import timezone


# Create your models here.
class UserManager(BaseUserManager):
    """
    Custom User Model manager where username is the unique 
    identifiers for authentication instead of usernames.
    """
    def create_user(self, username, password, **extra_fields):
        """
        create and save a user with the given username and password and extra_fields.
        """
        if not username:
            raise ValueError(-('the username must be set'))
        # email = self.normalize_email(email)
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self, username, password, **extra_fields):
        """
        create and save a superuser with the given username and password.
        """
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_supervisor', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_verified', True)
        
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(-('superuser must have is_superuser=True'))
        if extra_fields.get('is_supervisor') is not True:
            raise ValueError(-('supervisor must have is_supervisor=True'))
        if extra_fields.get('is_staff') is not True:
            raise ValueError(-('staff must have is_staff=True'))
        if extra_fields.get('is_verified') is not True:
            raise ValueError(-('staffuser must have is_verified=True'))
        return self.create_user(username, password, **extra_fields)

    def create_supervisor(self, username, password, **extra_fields):
        extra_fields.setdefault('is_supervisor', True)
        extra_fields.setdefault('is_staff', True)
        
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(-('superuser must have is_superuser=True'))
        if extra_fields.get('is_supervisor') is not True:
            raise ValueError(-('supervisor must have is_supervisor=True'))
        if extra_fields.get('is_staff') is not True:
            raise ValueError(-('staff must have is_staff=True'))
        return self.create_user(username, password, **extra_fields)
   
    
class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User Model for app
    """
    username = models.CharField(max_length=255, unique=True)
    
    is_superuser = models.BooleanField(_('کاربر دسترسی سوپر دارد؟'), default=False)
    is_supervisor = models.BooleanField(_('کاربر دسترسی سوپروایزر دارد؟'),default=False)
    is_staff = models.BooleanField(_('کاربر دسترسی نویسنده دارد؟'),default=False)
    is_verified = models.BooleanField(_('احراز هویت کاربر تایید شده است؟'),default=False)
     
    REQUIRED_FIELDS = [] #ejbary kardan por shodan yek sery az fild ha
    USERNAME_FIELD = 'username'
    
    #created_date = models.DateTimeField(_('تاریخ ایجاد'),auto_now_add=True)
    #updated_date = models.DateTimeField(_('تاریخ آخرین به روز رسانی'),auto_now=True)
    created_date = jmodels.jDateTimeField(_('تاریخ ایجاد'), auto_now_add=True)
    updated_date = jmodels.jDateTimeField(_('تاریخ آخرین به روز رسانی'),auto_now=True)
    
    objects = UserManager()

    def __str__(self) -> str:
        return self.username

    class Meta:
        ordering = ['-updated_date']
        verbose_name = 'کاربر'
        verbose_name_plural = 'کاربر ها'


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(_('نام'), max_length=255)
    last_name = models.CharField(_('نام خانوادگی'),max_length=255)
    image = models.ImageField(_('تصویر'),null=True, blank=True)
    description = models.TextField(_('توضیحات'),null=True, blank=True)
    sex = models.CharField(_('جنسیت'), max_length=32, choices=[('مرد', 'مرد'), ('زن', 'زن'), ('ترجیح میدهم نگویم', 'ترجیح میدهم نگویم')], null=True, blank=True)
    # age = models.CharField(_('سن'), max_length=10, null=True, blank=True)
    date_of_birth = jmodels.jDateField(_('تاریخ تولد'), null=True, blank=True)
    province = models.CharField(_('استان'), max_length=255, null=True, blank=True)
    city = models.CharField(_('شهر'), max_length=255, null=True, blank=True)
    job = models.CharField(_('شغل'), max_length=255, null=True, blank=True)
    education = models.CharField(_('تحصیلات'), max_length=255, null=True, blank=True)
    created_date = jmodels.jDateTimeField(_('تاریخ ایجاد'), auto_now_add=True)
    updated_date = jmodels.jDateTimeField(_('تاریخ آخرین به روز رسانی'),auto_now=True)
    
    USERNAME_FIELD = 'user'
    REQUIRED_FIELDS = [] 

    def __str__(self) -> str:
        return self.user.username

    class Meta:
        ordering = ['-updated_date']
        verbose_name = 'پروفایل'
        verbose_name_plural = 'پروفایل ها'

@receiver(post_save, sender=User)
def save_profile(sender, instance, created, **kwargs):
    if created:
        profile = Profile.objects.create(user=instance)
        profile.first_name = instance.username
        profile.save()
