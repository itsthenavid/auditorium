from django.shortcuts import render

from .models import Page

# Create your views here.

def index(request):
    """
    Index page view.
    """
    
    # Get the index page object
    index_page = Page.objects.get(is_active=True)

    # Render the index page template with the context
    return render(
        request,
        "pages/index.html",
        {
            "index_page": index_page,
        },
    )
