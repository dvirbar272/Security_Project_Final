# Communication LTD Security Project

A small Django demo showcasing secure and intentionally vulnerable flows.

## Run
```powershell
cd Security_Project_Final
python -m venv .venv
.\.venv\Scripts\activate
# or (macOS/Linux): source .venv/bin/activate
pip install django
pip install django-axes
python manage.py migrate
python manage.py runserver
```


## Admin user
Create an admin user for the Django admin panel:
```powershell
python manage.py createsuperuser
```
Then open `http://127.0.0.1:8000/admin/` and sign in.

Base URL: `http://127.0.0.1:8000`



## Endpoints
Secure:
- `/secure/register/`
- `/secure/login/`
- `/secure/change-password/`
- `/secure/forgot/`
- `/secure/add-customer/`

Vulnerable:
- `/vulnerable/register/`
- `/vulnerable/login/`
- `/vulnerable/change-password/`
- `/vulnerable/forgot/`
- `/vulnerable/add-customer/`
