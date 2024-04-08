from django import forms

from .models import Category, Article

# Create your forms here.


class CategoryForm(forms.ModelForm):

    class Meta:
        model = Category
        fields = "__all__"
        widgets = {
            "description": forms.Textarea
        }


class ArticleForm(forms.ModelForm):

    class Meta:
        model = Article
        fields = "__all__"
        widgets = {
            "description": forms.Textarea
        }
