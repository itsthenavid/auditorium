from django import template
from django.utils.safestring import mark_safe

# Create your customized Django Template Tags here.

register = template.Library()

@register.simple_tag(takes_context=True)
def static_dynamic_path(context, filepath):
    """
    Returns the full static path prefixing LANGUAGE_CODE folder automatically.
    Example usage:
        {% asset_path 'css/style.css' %}
    If LANGUAGE_CODE = 'fa' will return:
        /static/fa/css/style.css
    """
    request = context.get('request')
    lang = getattr(request, 'LANGUAGE_CODE', 'en') if request else 'en'
    path = f"{lang}/{filepath}"
    # use static() to get full static URL
    from django.templatetags.static import static
    url = static(path)
    return mark_safe(url)
