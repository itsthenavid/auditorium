from django.urls import path

from .views import PostDetailView, PostListView

# Create your URLs here.

app_name = "documents"

urlpatterns = [
    path("<slug:slug>/", PostDetailView.as_view(), name="post-detail"),
    path("", PostListView.as_view(), name="post-list"),
]
