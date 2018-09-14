#! /usr/bin/env python3
# coding: utf-8
from django.test import TestCase
from django.urls import reverse
from django.db.models import Q
from django.contrib import auth
from django.contrib.auth.models import User
from ..models import Profile



# Create your tests here.
class RegisterPageTestCase(TestCase):
    
    @classmethod
    def setUpTestData(cls):
        username = 'test-ref'
        mail = 'test-ref@register.com'
        password = 'ref-test-view'
        password_check = 'ref-test-view'
        User.objects.create_user(username, mail, password)

    def test_register_page_get(self):
        """
        Just it tests if the register page is available
        """
        response = self.client.get(reverse('register'))
        self.assertEqual(response.status_code, 200)

    def test_register_page_success_registration(self):
        """
        This method tests the adequate redirection when a registration
        is correctly done
        """

        data = {
            'username' : 'test-page',
            'mail' : 'unit-test@register.com',
            'password': 'unit-test-view',
            'password_check': 'unit-test-view',
        }

        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('log_in'))

    def test_register_page_fail_registration(self):
        """
        This method tests the fact that ny user is created when we want to
        register with an existing username
        """

        data = {
            'username' : 'test-ref',
            'mail' : 'unit-test@register.com',
            'password': 'unit-test-view',
            'password_check': 'unit-test-view',
        }

        user = User.objects.filter(Q(username="test-page"), Q(email="unit-test@register.com"))
        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(user), 0)

    # Come back to test this three elements below:
    # Test when we register that the user created is inactive
    # Test that a mail is sent when a registration is done
    # Test that the user field is_active is True when the link is clicked

class LoginPageTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        username = 'username-existing'
        mail = 'test-ref@register.com'
        password = 'existing-ref'
        password_check = 'existing-ref'
        User.objects.create_user(username, mail, password)
    
    def test_login_page_get(self):
        """
        Just it tests if the login page is available
        """
        response = self.client.get(reverse('log_in'))
        self.assertEqual(response.status_code, 200)
    
    def test_login_page_success_connexion(self):
        """
        The method tests the behavior of the app when a connexion is
        correctly realized
        """

        data = {
            'username' : 'username-existing',
            'password' : 'existing-ref',
        }

        response = self.client.post(reverse('log_in'), data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('homepage'))

        user = auth.get_user(self.client)
        self.assertTrue(user.is_authenticated)

    def test_login_page_fail_connexion_username(self):
        """
        The method tests the behavior of the app when a connexion
        is done with a wrong username
        """

        data = {
            'username' : 'unknown',
            'password' : 'existing-ref',
        }

        response = self.client.post(reverse('log_in'), data)
        self.assertEqual(response.status_code, 200)
        
        user = auth.get_user(self.client)
        self.assertFalse(user.is_authenticated)

    def test_login_page_fail_connexion_password(self):
        """
        The method tests the behavior of the app when a connexion
        is done with a wrong password
        """

        data = {
            'username' : 'username-existing',
            'password' : 'unknown-ref',
        }

        response = self.client.post(reverse('log_in'), data)
        self.assertEqual(response.status_code, 200)
        
        user = auth.get_user(self.client)
        self.assertFalse(user.is_authenticated)

class LogOutPageTestCase(TestCase):

    def test_logout_page(self):
        """
        The method tests the behavior of the app when a logout
        is done
        """
        response = self.client.get(reverse('log_out'))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('log_in'))
