# from django.shortcuts import render
from django.views.generic import TemplateView

from .models import Page

# Create your views here.


class IndexView(TemplateView):
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
        return context
    

class AboutView(TemplateView):
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
        context["about_page"] = Page.objects.get(is_active=True)
        return context
