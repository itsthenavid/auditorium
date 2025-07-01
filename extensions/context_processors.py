# Create a context processors file to handle language direction based on the current language code.

RTL_LANGUAGES = ["fa", "ckb"] 

def get_direction(code: str) -> str:
    """Return 'rtl' for rtl languages else 'ltr'."""
    return "rtl" if code in RTL_LANGUAGES else "ltr"

def direction_context(request):
    code = getattr(request, "LANGUAGE_CODE", "en")
    return {
        "LANGUAGE_CODE": code,
        "LANG_DIRECTION": get_direction(code),
    }
