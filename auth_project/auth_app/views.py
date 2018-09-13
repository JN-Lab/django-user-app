from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import HttpResponse
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.core.mail import EmailMessage

from .forms import LoginForm, RegisterForm
from .models import Profile
from .tokens import account_activation_token

# Create your views here.
def login(request):
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
            if not username_already_exist and password == password_check:
                user = User.objects.createuser(username, mail, password, is_active=False)
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

            else:
                pass
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