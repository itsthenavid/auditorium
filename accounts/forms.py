from django import forms
from django.utils.translation import gettext_lazy as _

from allauth.account.forms import SignupForm

from accounts.models import UserModel

# Create your custom forms here.

class CustomSignupForm(SignupForm):
    """
    Custom signup form for the UserModel.
    This form extends the default SignupForm from allauth and adds
    additional fields for the UserModel.
    It includes fields for avatar, name, email, username, password1,
    password2, and bio.
    """

    avatar = forms.ImageField(required=False, label="Avatar")
    name = forms.CharField(max_length=150, required=False, label="Full Name or Nickname")
    email = forms.EmailField(required=False, label="Email Address")
    username = forms.CharField(max_length=150, required=True, label="Username")
    password1 = forms.CharField(widget=forms.PasswordInput, required=True, label="Password1")
    password2 = forms.CharField(widget=forms.PasswordInput, required=True, label="Password2")
    bio = forms.CharField(widget=forms.Textarea, required=False, label="Bio")

    class Meta:
        model = UserModel
        fields = ['avatar', 'username', 'name', 'email', 'bio', 'password1', "password2"]
        
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Username'}),
            "bio": forms.Textarea(attrs={'placeholder': 'Bio'}),
            'password1': forms.PasswordInput(attrs={'placeholder': 'Password'}),
            'password2': forms.PasswordInput(attrs={'placeholder': 'Confirm Password'}),
        }

    def save(self, request):

        user = super(CustomSignupForm, self).save(request)
        user.name = self.cleaned_data['name']
        user.avatar = self.cleaned_data.get('avatar')
        user.bio = self.cleaned_data.get('bio')

        avatar_file = request.FILES.get("avatar_file")
        avatar_default = request.POST.get("avatar_default")

        if avatar_file:
            # Save the uploaded file to user's avatar
            user.avatar = avatar_file
        else:
            # Set avatar as path to default selected image
            user.avatar = f"{avatar_default}".replace("/static/en/img/", "defaults/accounts/")


        user.save()
        return user
    

class UserProfileForm(forms.ModelForm):
    name = forms.CharField(
        max_length=100,
        required=False,
        label=_("Name"),
        help_text=_("Enter your full name.")
    )
    bio = forms.CharField(
        max_length=500,
        required=False,
        label=_("Bio"),
        help_text=_("Write a short bio about yourself."),
        widget=forms.Textarea(attrs={'rows': 3})
    )

    class Meta:
        model = UserModel
        fields = ['avatar']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            self.fields['name'].initial = self.instance.name
            self.fields['bio'].initial = self.instance.bio

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.set_current_language(self.instance.get_current_language())
        instance.name = self.cleaned_data['name']
        instance.bio = self.cleaned_data['bio']
        if commit:
            instance.save()
        return instance
