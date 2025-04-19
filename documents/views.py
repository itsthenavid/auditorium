# from django.shortcuts import render
from django.views.generic import ListView

from .models import Hall, Post

# Create your views here.


class HallListView(ListView):
    """
    
    """
    
    model = Hall
    template_name = "documents/halls/list.html"


class PostListView(ListView):
    """
    """

    model = Post
    template_name = "documents/posts/list.html"
