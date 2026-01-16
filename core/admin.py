from django.contrib import admin
from .models import Sector, Package, Customer, UserAccount, PasswordHistory

admin.site.register(Sector)
admin.site.register(Package)
admin.site.register(Customer)
admin.site.register(UserAccount)
admin.site.register(PasswordHistory)
