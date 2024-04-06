from django.urls import path

from .views import article_list_view, article_detail_view

# Create your URL Patterns here.

app_name = "clusters"

urlpatterns = [
    path("", article_list_view, name="article_list"),
    path("<slug:slug>/", article_detail_view, name="article_detail"),
]

