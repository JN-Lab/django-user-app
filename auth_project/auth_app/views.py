from django.shortcuts import render
from .forms import LoginForm, RegisterForm

# Create your views here.
def login(request):
    login_form = LoginForm()
    return render(request, 'login.html', locals())

def register(request):
    register_form = RegisterForm()
    return render(request, 'register.html', locals())