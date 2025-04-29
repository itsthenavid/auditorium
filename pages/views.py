# from django.shortcuts import render
from django.views.generic import TemplateView

from .models import Page
from documents.models import Hall, Post

# Create your views here.


class IndexPageView(TemplateView):
    """
    Index view for the application.
    """

    template_name = "pages/index.html"

    def get_context_data(self, **kwargs):
        """
        Get the context data for the index view.
        This method retrieves the active page from the database and adds it to the context.
        """
        context = super().get_context_data(**kwargs)
        context["context"] = Page.objects.get(is_active=True)
        context["pinned_post_1"] = Post.activated.filter(pinned=True)[0]
        context["pinned_post_2"] = Post.activated.filter(pinned=True)[1]
        context["pinned_post_3"] = Post.activated.filter(pinned=True)[2]
        context["pinned_post_4"] = Post.activated.filter(pinned=True)[3]

        context["pinned_hall_1"] = Hall.activated.filter(pinned=True)[0]
        context["pinned_hall_2"] = Hall.activated.filter(pinned=True)[1]
        context["pinned_hall_3"] = Hall.activated.filter(pinned=True)[2]
        context["pinned_hall_4"] = Hall.activated.filter(pinned=True)[3]

        return context
    

class IntroductionPageView(TemplateView):
    """
    About view for the application.
    """

    template_name = "pages/about.html"

    def get_context_data(self, **kwargs):
        """
        Get the context data for the about us view.
        This method retrieves the active page from the database and adds it to the context.
        """
        context = super().get_context_data(**kwargs)
        context["context"] = Page.objects.get(is_active=True)
        return context
