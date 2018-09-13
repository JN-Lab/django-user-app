from django.shortcuts import render
from django.contrib.auth.models import User

from .forms import LoginForm, RegisterForm
from .models import Profile


# Create your views here.
def login(request):
    login_form = LoginForm()
    return render(request, 'login.html', locals())

def register(request):
    if request.method == "POST":
        register_form = RegisterForm(request.POST)
        if register_form.is_valid():
            username = register_form.cleaned_data["username"]
            mail = register_form.cleaned_data["mail"]
            password = register_form.cleaned_data["password"]
            password_check = register_form.cleaned_data["password_check"]

            username_already_exist = User.objects.filter(username=username).exists()
            if not username_already_exist and password == password_check:
                user = User.objects.createuser(username, mail, password, is_active=False)
                user_profile = Profile(user=user)
                user_profile.save()

            else:
                pass
    else:
        register_form = RegisterForm()
        return render(request, 'register.html', locals())