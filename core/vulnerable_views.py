from django.db import connection
from django.shortcuts import render

"""
Intentional vulnerabilities:
- Raw SQL with string interpolation (SQLi) for register/login/add customer.
- Stored XSS: customer name rendered unescaped in template.
- No password policy, no hashing/salting.
"""


def register_vulnerable(request):
    message = ""
    if request.method == "POST":
        username = request.POST.get("username", "")
        email = request.POST.get("email", "")
        password = request.POST.get("password", "")
        with connection.cursor() as cursor:
            # SQL injection vulnerable
            cursor.execute(
                f"INSERT INTO core_useraccount (username, email, salt, password_hash, login_attempts) "
                f"VALUES ('{username}', '{email}', '', '{password}', 0)"
            )
        message = "Vulnerable registration completed (no hashing, SQLi possible)."
    return render(request, "vulnerable/register.html", {"message": message})


def login_vulnerable(request):
    message = ""
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT id FROM core_useraccount WHERE username='{username}' AND password_hash='{password}'"
            )
            row = cursor.fetchone()
            if row:
                message = "Login success (vulnerable, SQLi-able)."
            else:
                message = "Invalid credentials."
    return render(request, "vulnerable/login.html", {"message": message})


def change_password_vulnerable(request):
    message = ""
    if request.method == "POST":
        username = request.POST.get("username", "")
        new_password = request.POST.get("new_password", "")
        with connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE core_useraccount SET password_hash='{new_password}' WHERE username='{username}'"
            )
        message = "Password changed without validation (vulnerable)."
    return render(request, "vulnerable/change_password.html", {"message": message})


def add_customer_vulnerable(request):
    message = ""
    created_name = ""
    if request.method == "POST":
        first_name = request.POST.get("first_name", "")
        last_name = request.POST.get("last_name", "")
        email = request.POST.get("email", "")
        phone = request.POST.get("phone_number", "")
        # Stored XSS: names are saved and rendered without escaping
        with connection.cursor() as cursor:
            cursor.execute("INSERT OR IGNORE INTO core_sector (id, user_type) VALUES (1, 'vulnerable-sector')")
            cursor.execute("INSERT OR IGNORE INTO core_package (id, package_name, package_size) VALUES (1, 'vulnerable-package', 0)")
            cursor.execute(
                "INSERT INTO core_customer (first_name, last_name, email, phone_number, sector_id, package_id) "
                f"VALUES ('{first_name}', '{last_name}', '{email}', '{phone}', 1, 1)"
            )
        created_name = f"{first_name} {last_name}"
        message = "Customer added (vulnerable: raw SQL + stored XSS)."
    return render(
        request,
        "vulnerable/add_customer.html",
        {"message": message, "created_name": created_name},
    )


def forgot_password_vulnerable(request):
    message = ""
    token = ""
    if request.method == "POST":
        username = request.POST.get("username", "")
        token = request.POST.get("token", "static-token")
        with connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE core_useraccount SET reset_token='{token}' WHERE username='{username}'"
            )
        message = "Static token set (vulnerable, predictable)."
    return render(request, "vulnerable/forgot_password.html", {"message": message, "token": token})
