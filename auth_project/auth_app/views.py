from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import HttpResponse
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.core.mail import EmailMessage

from .forms import LoginForm, RegisterForm, PasswordResetMail
from .models import Profile
from .tokens import account_activation_token

# Create your views here.
def log_in(request):
    if request.method == "POST":
        login_form = LoginForm(request.POST)
        if login_form.is_valid():
            username = login_form.cleaned_data["username"]
            password = login_form.cleaned_data["password"]
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                return redirect(reverse('homepage'), locals())
            else:
                messages.error(request, """Your username or password is uncorrect. Please try again.""")
                return render(request, 'login.html', locals())
    else:
        login_form = LoginForm()
        return render(request, 'login.html', locals())

def register(request):
    """
    This view manage the resgistration process
    """
    if request.method == "POST":
        register_form = RegisterForm(request.POST)
        if register_form.is_valid():
            username = register_form.cleaned_data["username"]
            mail = register_form.cleaned_data["mail"]
            password = register_form.cleaned_data["password"]
            password_check = register_form.cleaned_data["password_check"]

            username_already_exist = User.objects.filter(username=username).exists()
            mail_already_exist = User.objects.filter(email=mail).exists()
            if not username_already_exist and not mail_already_exist and password == password_check:
                user = User.objects.create_user(username, mail, password, is_active=False)
                user_profile = Profile(user=user)
                user_profile.save()

                current_site = get_current_site(request)
                mail_subject = "Activate your account"
                message = render_to_string('acc_activate_email.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                    'token': account_activation_token.make_token(user),
                })
                to_email = mail
                email = EmailMessage(
                    mail_subject,
                    message,
                    to=[to_email]
                )
                email.send()

                messages.success(request, """An email had been sent to you. Please confirm your email address
                    to finalize your registration""")
                return redirect('log_in')

            else:
                if username_already_exist:
                    messages.error(request, """The username already exists. Please, change it.""")
                elif mail_already_exist:
                    messages.error(request, """The mail already exists. Please login with your existing account.""")
                    return redirect('log_in')
                else:
                    messages.error(request, """There is an error in the password. Please try again""")

                return render(request, 'register.html', locals())
    else:
        register_form = RegisterForm()
        return render(request, 'register.html', locals())

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        return HttpResponse("""Thank you for your email confirmation. Now you can login your account.""")
    else:
        return HttpResponse("""Activation link is invalid!""")

def log_out(request):
    logout(request)
    return redirect(reverse('log_in'), locals())

@login_required(login_url='/login/')
def homepage(request):
    return render(request, 'homepage_example.html', locals())

# For password reset process

def password_forgotten(request):
    """
    This view will:
        - generate a form for get the mail
        - check if there is an account linked to this mail
        - send a mail if there is or error message if not
    """
    if request.method == "POST":
        pass
    else:
        password_forgotten_form = PasswordResetMail()
        return render(request, 'password_reset_mail.html', locals())

def password_reset_activate(request, uidb64, token):
    """
    This view will:
        - check if the token is valid
            - ask for new password if the token is valid
                - register the new password if ok + redirect on login page
                - message error if there is a problem in the new password
            - error message if not + rediect on login page
    """
    pass
