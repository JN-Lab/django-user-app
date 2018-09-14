"""auth_project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from auth_app import views as auth_views

urlpatterns = [
    path('login/', auth_views.log_in, name="log_in"),
    path('logout/', auth_views.log_out, name="log_out"),
    path('register/', auth_views.register, name="register"),
    path('activate/<uidb64>/<token>/', auth_views.activate, name="activate"),
    path('password-forgotten/', auth_views.password_forgotten, name="password_forgotten"),
    path('password-reset-activate/<uidb64>/<token>/', auth_views.password_reset_activate, name="password_reset_activate"),
    path('password-reset/', auth_views.password_reset_new, name="password_reset_new"),
    path('home/', auth_views.homepage, name="homepage"),
    path('admin/', admin.site.urls),
]
