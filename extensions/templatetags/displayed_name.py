from django import template

# Create your customized Django Template Tags here.

register = template.Library()

@register.simple_tag(takes_context=True)
def displayed_name(context, user):
    lang_code = context.get('request').LANGUAGE_CODE if 'request' in context else 'en'
    try:
        profile_name = user.profiles.get(lang_code, {}).get('name', '').strip()
        if profile_name:
            return profile_name
    except (AttributeError, TypeError):
        pass

    full_name = ' '.join(filter(None, [user.first_name.strip(), user.last_name.strip()]))
    if full_name:
        return full_name

    return user.username
