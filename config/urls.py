"""
URL configuration for 'Auditorium' project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path
from django.urls import include
from django.conf.urls.i18n import i18n_patterns
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # i18n path for internationalization
    # This is the path that will be used for language switching (Prefixes)
    path('i18n/', include('django.conf.urls.i18n')),
]

# The i18n_patterns function is used to add language prefix to the URLs
# based on the user's language preference.
urlpatterns += i18n_patterns(
    # Django default URLs
    path('admin/', admin.site.urls),

    # 'allauth' URLs
    path("allauth/", include("allauth.urls")),
    
    path("", include("pages.urls")),
)

# Serve media files in development
# This is only for development purposes and should not be used in production.
# This tells Django to serve media files from the MEDIA_URL to the MEDIA_ROOT
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
