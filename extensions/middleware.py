from django.utils import translation
from django.conf import settings

# Create your customized Middlewares here.


class UserLanguageMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        current_lang = translation.get_language()
        url_lang = getattr(request, 'LANGUAGE_CODE', None)

        if request.user.is_authenticated:
            try:
                user_lang = request.user.settings.language
                if not url_lang:
                    session_lang = request.session.get('django_language')
                    if not session_lang or session_lang == user_lang:
                        if user_lang != current_lang:
                            translation.activate(user_lang)
                            request.LANGUAGE_CODE = user_lang
                            request.session['django_language'] = user_lang
            except AttributeError:
                pass

        response = self.get_response(request)
        return response
