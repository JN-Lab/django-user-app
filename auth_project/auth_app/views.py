from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.core.mail import EmailMessage
from .forms import LoginForm, RegisterForm, PasswordResetMail, PasswordResetNew
from .models import Profile
from .tokens import account_activation_token

def log_in(request):
    """
    This view manages the connexion of the user
    """
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
                messages.error(request, """Votre nom d'utilisateur ou votre mot de passe est incorrect.""")
                return render(request, 'login.html', locals())
    else:
        login_form = LoginForm()
        return render(request, 'login.html', locals())

def register(request):
    """
    This view manages the resgistration process
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
                mail_subject = "Activez votre compte"
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

                messages.success(request, """Un email vous a été envoyé. Veuillez cliquer sur le lien pour finaliser
                    votre inscription s'il vous plait""")
                return redirect('log_in')

            else:
                if username_already_exist:
                    messages.error(request, """Ce nom d'utilisateur existe déjà. Veuillez en choisir un autre 
                        s'il vous plaît.""")
                elif mail_already_exist:
                    messages.error(request, """L'email est déjà associé à un compte utilisateur. Veuillez
                        vous connecter avec vos identifiants s'il vous plaît.""")
                    return redirect('log_in')
                else:
                    messages.error(request, """Il y a une erreur au niveau du mot de passe. Veuillez réessayer
                        s'il vous plaît.""")

                return render(request, 'register.html', locals())
    else:
        register_form = RegisterForm()
        return render(request, 'register.html', locals())

def activate(request, uidb64, token):
    """
    This view manages the email validation process
    """
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        messages.success(request, """Merci pour avoir confirmé votre email. Vous pouvez désormais 
            vous connecter à votre compte.""")
        return redirect(reverse('log_in'), locals())
    else:
        messages.error(request, """Le lien d'activation n'est pas valide!""")
        return redirect(reverse('register'), locals())

def log_out(request):
    """
    This mail manages the logout process
    """
    logout(request)
    return redirect(reverse('log_in'), locals())

def password_forgotten(request):
    """
    This view will:
        - generate a form for get the mail
        - check if there is an account linked to this mail
        - send a mail if there is or error message if not
    """
    if request.method == "POST":
        password_forgotten_form = PasswordResetMail(request.POST)
        if password_forgotten_form.is_valid():
            mail = password_forgotten_form.cleaned_data["mail"]
            user_already_exist = User.objects.filter(email=mail).exists()
            if user_already_exist:
                user = User.objects.get(email=mail)
                current_site = get_current_site(request)

                mail_subject = "Réinitialisez votre mot de passe"
                message = render_to_string('acc_activate_reset_password.html', {
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

                messages.success(request, """Un email vous a été envoyé. Veuillez cliquer dessus sur le lien
                    pour réinitialiser votre mot de passe""")
                return render(request, 'password_reset_mail.html', locals())
            else:
                messages.error(request, "Il n'existe aucun compte associé à cet email.")
                return render(request, 'password_reset_mail.html', locals())

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
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        login(request, user)
        return redirect(reverse('password_reset_new'), locals())
    else:
        messages.error(request, """Le lien d'activation n'est pas valide!""")
        return redirect(reverse('log_in'), locals())

def password_reset_new(request):
    """
    This view will change the password of the user
    """

    if request.method == "POST":
        password_reset_form = PasswordResetNew(request.POST)
        if password_reset_form.is_valid():
            password = password_reset_form.cleaned_data["password"]
            password_check = password_reset_form.cleaned_data["password_check"]
            user = User.objects.get(username=request.user.username)
            if user.is_authenticated and password == password_check:
                user.set_password(password)
                user.save()
                logout(request)
                messages.success(request, """Votre mot de passe a été modifié.
                    Vous pouvez désormais vous connecter avec votre nouveau mot de passe.""")
                return redirect(reverse('log_in'), locals())
            else:
                messages.error(request, """Il y a un problème concernant votre compte.
                    Nous travaillons actuellement dessus.""")
                return redirect(reverse('register'), locals())
    else:
        password_reset_form = PasswordResetNew()
        return render(request, 'password_reset_new.html', locals())

@login_required(login_url='/login/')
def homepage(request):
    """
    This is just a view to have an homepage for the example.
    Usually, this view will be out of the application in another project
    """
    return render(request, 'homepage_example.html', locals())
