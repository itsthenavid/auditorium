from django.shortcuts import render
from django.views.generic import DetailView, ListView
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector

from parler.utils.context import switch_language
from parler.utils import get_active_language_choices
from django.utils.translation import get_language
from parler.utils.context import switch_language

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
    

class PostSearchView(ListView):
    model = Post
    template_name = "documents/search_results.html"
    context_object_name = "posts"

    def get_queryset(self):
        query = self.request.GET.get("q", "")
        language = get_language()  # 'fa', 'ku', ...

        if not query:
            return Post.objects.none()

        search_vector = (
            SearchVector("translations__title", weight="A", config="simple") +
            SearchVector("translations__content", weight="B", config="simple")
        )
        search_query = SearchQuery(query, config="simple")

        # فقط translationهای مربوط به زبان فعال
        qs = Post.objects.filter(translations__language_code=language)
        qs = qs.annotate(
            rank=SearchRank(search_vector, search_query)
        ).filter(
            rank__gte=0.1,
            status='1',
            is_active=True,
        ).order_by("-rank", "-publish_datetime")

        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["query"] = self.request.GET.get("q", "")
        return context
