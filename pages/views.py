from django.shortcuts import render
from django.views.generic import TemplateView

# Create your views here.


class IndexPageTemplateView(TemplateView):
    """
    A view that renders the index page.
    """

    template_name = "pages/index.html"

    def get_context_data(self, **kwargs):
        """
        Add additional context data to the template.
        """
        context = super().get_context_data(**kwargs)
        context["title"] = "Index Page"
        return context
