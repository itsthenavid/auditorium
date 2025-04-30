from django.urls import path

from .views import HallDetailView, HallListView, PostDetailView, PostListView, PostSearchView

# Create your URLs here.

app_name = "documents"

urlpatterns = [
    path("hall/<slug:slug>/", HallDetailView.as_view(), name="hall-detail"),
    path("halls/", HallListView.as_view(), name="hall-list"),

    path("post/<slug:slug>/", PostDetailView.as_view(), name="post-detail"),
    path("posts/", PostListView.as_view(), name="post-list"),
    path("posts/search/", PostSearchView.as_view(), name="post-search"),
]
