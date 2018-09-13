from django.test import TestCase
from django.urls import reverse
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
        Just test if the register page is available
        """
        response = self.client.get(reverse('register'))
        self.assetEqual(response.status_code, 200)

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
        self.assetEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('log_in'))