from django.urls import path

from . import secure_views, vulnerable_views

urlpatterns = [
    # Secure endpoints
    path("secure/register/", secure_views.register_secure, name="secure_register"),
    path("secure/login/", secure_views.login_secure, name="secure_login"),
    path("secure/change-password/", secure_views.change_password_secure, name="secure_change_password"),
    path("secure/forgot/", secure_views.forgot_password_secure, name="secure_forgot_password"),
    path("secure/add-customer/", secure_views.add_customer_secure, name="secure_add_customer"),

    # Vulnerable endpoints
    path("vulnerable/register/", vulnerable_views.register_vulnerable, name="vulnerable_register"),
    path("vulnerable/login/", vulnerable_views.login_vulnerable, name="vulnerable_login"),
    path("vulnerable/change-password/", vulnerable_views.change_password_vulnerable, name="vulnerable_change_password"),
    path("vulnerable/forgot/", vulnerable_views.forgot_password_vulnerable, name="vulnerable_forgot_password"),
    path("vulnerable/add-customer/", vulnerable_views.add_customer_vulnerable, name="vulnerable_add_customer"),
]
