import hashlib
import os
from django.db import transaction
from django.shortcuts import render
from django.utils import timezone

from .models import Customer, Package, Sector, UserAccount, PasswordHistory
from .security import (
    generate_salt,
    hmac_hash_password,
    load_password_policy,
    validate_password,
    verify_password,
)


def _get_policy():
    return load_password_policy()


def _default_sector_and_package():
    sector, _ = Sector.objects.get_or_create(user_type="default")
    package, _ = Package.objects.get_or_create(package_name="basic", defaults={"package_size": 1024})
    return sector, package


def register_secure(request):
    policy = _get_policy()
    message = ""
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "")

        ok, error = validate_password(password, policy)
        if not ok:
            message = error
        elif UserAccount.objects.filter(username=username).exists():
            message = "Username already exists."
        else:
            salt = generate_salt()
            password_hash = hmac_hash_password(salt, password)
            sector, package = _default_sector_and_package()
            with transaction.atomic():
                user = UserAccount.objects.create(
                    username=username,
                    email=email,
                    salt=salt,
                    password_hash=password_hash,
                    sector=sector,
                    package=package,
                )
                PasswordHistory.objects.create(user=user, password_hash=password_hash)
            message = "Secure registration successful."

    return render(request, "secure/register.html", {"message": message})


def login_secure(request):
    policy = _get_policy()
    message = ""
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        try:
            user = UserAccount.objects.get(username=username)
        except UserAccount.DoesNotExist:
            user = None
        if not user:
            message = "Invalid credentials."
        elif user.login_attempts >= policy.get("login_attempts_limit", 3):
            message = "Account locked due to too many attempts."
        elif verify_password(user.salt, password, user.password_hash):
            user.login_attempts = 0
            user.save(update_fields=["login_attempts"])
            message = "Login success (secure)."
        else:
            user.login_attempts += 1
            user.save(update_fields=["login_attempts"])
            message = "Invalid credentials."

    return render(request, "secure/login.html", {"message": message})


def change_password_secure(request):
    policy = _get_policy()
    message = ""
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        old_password = request.POST.get("old_password", "")
        new_password = request.POST.get("new_password", "")
        token = request.POST.get("token", "").strip()

        try:
            user = UserAccount.objects.get(username=username)
        except UserAccount.DoesNotExist:
            user = None

        if not user:
            message = "User not found."
        else:
            
            is_valid_reset = False
            if token:
                
                if user.reset_token and token == user.reset_token:
                    is_valid_reset = True
                else:
                    message = "Invalid reset token."

           
            if not message and not is_valid_reset:
                if not verify_password(user.salt, old_password, user.password_hash):
                    message = "Old password incorrect."

            
            if not message:
                ok, error = validate_password(new_password, policy)
                if not ok:
                    message = error
                else:
                    new_hash = hmac_hash_password(user.salt, new_password)
                    
                    recent_hashes = list(
                        user.password_history.order_by("-created_at")[: policy.get("password_history_limit", 3)]
                        .values_list("password_hash", flat=True)
                    )
                    if new_hash in recent_hashes:
                        message = "New password was used recently."
                    else:
                        
                        user.password_hash = new_hash
                        
                        user.reset_token = None
                        user.reset_created_at = None
                        user.save(update_fields=["password_hash", "reset_token", "reset_created_at"])
                        
                        PasswordHistory.objects.create(user=user, password_hash=new_hash)
                        
                        
                        keep = policy.get("password_history_limit", 3)
                        extra_qs = user.password_history.order_by("-created_at")[keep:]
                        if extra_qs.exists():
                            user.password_history.filter(id__in=list(extra_qs.values_list("id", flat=True))).delete()
                        
                        if is_valid_reset:
                            message = "Password reset successfully (using token)."
                        else:
                            message = "Password changed securely."

    return render(request, "secure/change_password.html", {"message": message})

def forgot_password_secure(request):
    message = ""
    generated_token = ""
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        try:
            user = UserAccount.objects.get(username=username)
        except UserAccount.DoesNotExist:
            user = None
        if not user:
            message = "User not found."
        else:
            random_bytes = os.urandom(16)
            token = hashlib.sha1(random_bytes).hexdigest()
            user.reset_token = token
            user.reset_created_at = timezone.now()
            user.save(update_fields=["reset_token", "reset_created_at"])
            generated_token = token
            message = f"Reset token generated and (simulated) emailed to {user.email}."

    return render(request, "secure/forgot_password.html", {"message": message, "token": generated_token})


def add_customer_secure(request):
    message = ""
    created_name = ""
    if request.method == "POST":
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        email = request.POST.get("email", "").strip()
        phone = request.POST.get("phone_number", "").strip()
        sector, package = _default_sector_and_package()
        customer = Customer.objects.create(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone_number=phone,
            sector=sector,
            package=package,
        )
        created_name = str(customer)
        message = "Customer added (escaped output)."

    return render(
        request,
        "secure/add_customer.html",
        {
            "message": message,
            "created_name": created_name,
        },
    )
