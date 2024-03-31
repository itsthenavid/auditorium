from django.shortcuts import render

# Create your views here.

def index_page_view(request):
    template_name = None

    match request.LANGUAGE_CODE:
        case "en":
            template_name = "index_en"
        case _:
            template_name = "index_fa"

    return render(request, f"pages/{template_name}.html")
