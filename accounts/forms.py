from django import forms

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
        user.save()
        return user
