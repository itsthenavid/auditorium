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
