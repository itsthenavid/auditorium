from django.shortcuts import render
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404

from .models import Article

# Create your views here.


def article_list_view(request):
    articles = Article.actives.all()

    match request.LANGUAGE_CODE:
        case "en":
            template_name = "en/article_list"
        case _:
            template_name = "fa/article_list"
    
    return render(
        request,
        f"articles/{template_name}.html",
        context={
            "articles": articles,
        }
    )


def article_detail_view(request, slug):
    try:
        article = Article.actives.get(slug=slug)
    except ObjectDoesNotExist:
        raise Http404

    match request.LANGUAGE_CODE:
        case "en":
            template_name = "en/article_detail"
        case _:
            template_name = "fa/article_detail"
    
    return render(
        request,
        f"articles/{template_name}.html",
        context={
            "article": article,
        }
    )
