# from django.shortcuts import render
from django.views.generic import DetailView, ListView

from .models import Hall, Post

# Create your views here.


class HallDetailView(DetailView):
    """
    """

    model = Hall
    template_name = "documents/hall_detail.html"


class HallListView(ListView):
    """
    
    """
    
    model = Hall
    template_name = "documents/hall_list.html"

    paginate_by = 5


class PostDetailView(DetailView):
    """
    """

    model = Post
    template_name = "documents/post_detail.html"


class PostListView(ListView):
    """
    """

    model = Post
    template_name = "documents/post_list.html"
    
    paginate_by = 5
