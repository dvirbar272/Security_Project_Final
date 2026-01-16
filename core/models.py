from django.db import models
from django.utils import timezone

class Sector(models.Model):
    user_type = models.CharField(max_length=100)

    def __str__(self):
        return self.user_type

class Package(models.Model):
    package_name = models.CharField(max_length=100)
    package_size = models.IntegerField()  # Size in MB

    def __str__(self):
        return self.package_name
        
class Customer(models.Model):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)
    sector = models.ForeignKey('Sector', on_delete=models.CASCADE)
    package = models.ForeignKey('Package', on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class UserAccount(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    salt = models.CharField(max_length=128)
    password_hash = models.CharField(max_length=256)
    login_attempts = models.PositiveIntegerField(default=0)
    reset_token = models.CharField(max_length=128, null=True, blank=True)
    reset_created_at = models.DateTimeField(null=True, blank=True)
    sector = models.ForeignKey(Sector, null=True, blank=True, on_delete=models.SET_NULL)
    package = models.ForeignKey(Package, null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return self.username


class PasswordHistory(models.Model):
    user = models.ForeignKey(UserAccount, related_name="password_history", on_delete=models.CASCADE)
    password_hash = models.CharField(max_length=256)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} @ {self.created_at.isoformat()}"
