from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile

from .models import CustomUser

# Create your tests here.


class CustomUserModelTestCase(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="password",
            first_name="Test",
            last_name="User",
            bio="Test bio"
        )
    
    def test_user_creation(self):
        self.assertEqual(self.user.username, "testuser")
        self.assertEqual(self.user.email, "test@example.com")
        self.assertEqual(self.user.first_name, "Test")
        self.assertEqual(self.user.last_name, "User")
        self.assertEqual(self.user.bio, "Test bio")
        self.assertTrue(self.user.check_password("password"))
        self.assertTrue(self.user.is_active)
        self.assertFalse(self.user.is_staff)
        self.assertFalse(self.user.is_superuser)
        self.assertIsNotNone(self.user.date_joined)

    def test_unique_email_constraint(self):
        with self.assertRaises(Exception):
            CustomUser.objects.create_user(
                username="anotheruser",
                email="test@example.com",
                password="password"
            )

    def test_avatar_default_value(self):
        self.assertEqual(self.user.avatar.name, f"constants/{self.user.avatar.url.split('/')[-1]}")

    def test_user_name_generation(self):
        self.assertEqual(self.user.get_user_suggested_name(), "Test User")

    def test_avatar_thumbnail_generation(self):
        thumbnail_html = self.user.set_thumbnail_avatar()
        self.assertIn("<img src=", thumbnail_html)
        self.assertIn("style=\"height: 50px; width: 50px; border-radius: 50%;\"", thumbnail_html)

    def test_user_string_representation(self):
        self.assertEqual(str(self.user), "Test User")
        self.assertEqual(repr(self.user), "Test User")

    def test_change_user_attributes(self):
        self.user.first_name = "Updated"
        self.user.last_name = "User"
        self.user.email = "updated@example.com"
        self.user.bio = "Updated bio"
        self.user.save()
        updated_user = CustomUser.objects.get(pk=self.user.pk)
        self.assertEqual(updated_user.first_name, "Updated")
        self.assertEqual(updated_user.last_name, "User")
        self.assertEqual(updated_user.email, "updated@example.com")
        self.assertEqual(updated_user.bio, "Updated bio")

    def test_user_authentication(self):
        authenticated = CustomUser.objects.authenticate(username=self.user.username, password="password")
        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated, self.user)
        not_authenticated = CustomUser.objects.authenticate(username=self.user.username, password="wrong_password")
        self.assertIsNone(not_authenticated)

    def test_user_permissions(self):
        self.assertFalse(self.user.has_perm("some_permission"))

    def test_file_upload_for_avatar(self):
        avatar_file = SimpleUploadedFile("avatar.jpg", b"avatar_data", content_type="image/jpeg")
        self.user.avatar = avatar_file
        self.user.save()
        self.assertTrue(self.user.avatar.name.startswith("accounts/avatars/"))
    
    def test_user_deletion(self):
        user_count_before = CustomUser.objects.count()
        self.user.delete()
        user_count_after = CustomUser.objects.count()
        self.assertEqual(user_count_before - 1, user_count_after)

    def test_user_manager_methods(self):
        superuser = CustomUser.objects.create_superuser(
            username="admin",
            email="admin@example.com",
            password="adminpassword"
        )
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.is_staff)
