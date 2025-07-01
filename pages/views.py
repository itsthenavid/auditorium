from django.shortcuts import render

# Create your views here.

def index(request):
    """
    Render the index page with content from the IndexPage model.
    """
    from .models import IndexPage  # Import the model here to avoid circular imports
    index_page = IndexPage.objects.filter(is_active=True).first()
    
    context = {
        'index_page': index_page,
    }
    
    return render(request, 'pages/index.html', context)
