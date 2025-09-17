from django.urls import path

from . import views

# Create your URL Paths here.

app_name = "core"

urlpatterns = [
    path("post/create/", views.PostCreateView.as_view(), name="create_post"),
    path('post/ajax/', views.PostAjaxView.as_view(), name='post_ajax'),
    path('post/tinymce/upload/', views.TinyMCEUploadView.as_view(), name='tinymce_upload'),
]
