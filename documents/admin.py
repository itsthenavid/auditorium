from django.contrib import admin

from parler.admin import TranslatableAdmin

from .models import Hall, Post

# Register your models here.


@admin.register(Hall)
class HallAdmin(TranslatableAdmin):
    """
    Admin panel for the Hall model.
    This class is used to customize the admin panel for the Hall model
    and to add custom actions to the admin panel.
    """
    pass

    def get_queryset(self, request):
        # Ensure the admin uses the activated manager
        return Hall.objects.all()


@admin.register(Post)
class PostAdmin(TranslatableAdmin):
    """
    Admin panel for the Post model.
    This class is used to customize the admin panel for the Post model
    and to add custom actions to the admin panel.
    """
    pass

    def get_queryset(self, request):
        # Ensure the admin uses the activated manager
        return Post.objects.all()
