# from django.shortcuts import render
from django.views.generic import DetailView, ListView

from .models import Hall, Post

# Create your views here.


class HallDetailView(DetailView):
    """
    """

    model = Hall
    template_name = "documents/hall_detail.html"

    def get_queryset(self):
        return Hall.activated.all()
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add activated posts to the context
        context['activated_halls'] = Hall.activated.filter(parent=self.object)
        context['activated_posts'] = Post.activated.filter(hall=self.object)
        return context


class HallListView(ListView):
    """
    
    """
    
    model = Hall
    template_name = "documents/hall_list.html"

    paginate_by = 5

    def get_queryset(self):
        return Hall.activated.all()
    

class PostDetailView(DetailView):
    """
    """

    model = Post
    template_name = "documents/post_detail.html"

    def get_queryset(self):
        return Post.activated.all()


class PostListView(ListView):
    """
    """

    model = Post
    template_name = "documents/post_list.html"
    
    paginate_by = 5

    def get_queryset(self):
        return Post.activated.all()
