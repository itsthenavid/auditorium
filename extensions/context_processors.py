from managements.models import Settings

# Create a context processors file to handle language direction based on the current language code.

RTL_LANGUAGES = ["fa", "ckb"] 

def get_direction(code: str) -> str:
    """Return 'rtl' for rtl languages else 'ltr'."""
    return "rtl" if code in RTL_LANGUAGES else "ltr"

def direction_context(request):
    code = getattr(request, "LANGUAGE_CODE", "en")
    print(f"Language code in context: {code}")
    return {
        "LANGUAGE_CODE": code,
        "LANG_DIRECTION": get_direction(code),
    }

def user_settings(request):
    if request.user.is_authenticated:
        try:
            settings = request.user.settings
            return {'user_settings': settings}
        except Settings.DoesNotExist:
            return {'user_settings': None}
    return {'user_settings': None}
