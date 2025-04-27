from django import template

from bs4 import BeautifulSoup

# Create your template tags here.

register = template.Library()

@register.filter
def process_figures(content):
    if not content:
        return content
    soup = BeautifulSoup(content, 'html.parser')
    for figure in soup.find_all('figure'):
        img = figure.find('img')
        if not img:
            continue
        src = img.get('src', '')
        alt = img.get('alt', 'image')
        if not src or not src.startswith('/media/'):
            continue
        thumb_path = src.replace('blog/single/', 'blog/single/thumb/')
        new_figure = soup.new_tag('figure', attrs={'class': 'tt-blog-post-image'})
        a = soup.new_tag('a', attrs={
            'href': src,
            'class': 'tt-bpi-link lg-trigger',
            'data-exthumbnail': thumb_path,
            'data-cursor': 'View'
        })
        new_img = soup.new_tag('img', attrs={
            'class': 'tt-lazy',
            'src': '/static/assets/img/low-qlt-thumb.jpg',
            'data-src': src,
            'alt': alt
        })
        a.append(new_img)
        new_figure.append(a)
        figure.replace_with(new_figure)
    return str(soup)

@register.filter
def process_blockquotes(content):
    if not content:
        return content
    soup = BeautifulSoup(content, 'html.parser')
    for blockquote in soup.find_all('blockquote'):
        quote_text = ''.join(str(child) for child in blockquote.children if child.name == 'p')
        if not quote_text:
            quote_text = str(blockquote.text).strip()
        new_blockquote = soup.new_tag('blockquote', attrs={'class': 'open-quote'})
        new_blockquote.append(BeautifulSoup(quote_text, 'html.parser'))
        blockquote.replace_with(new_blockquote)
    return str(soup)

@register.filter
def localize_numbers_fa(value):
    numbers = {
        "0": "۰",
        "1": "۱",
        "2": "۲",
        "3": "۳",
        "4": "۴",
        "5": "۵",
        "6": "۶",
        "7": "۷",
        "8": "۸",
        "9": "۹",
    }

    for e, p in numbers.items():
        value = value.replace(e, p)
    
    return value

@register.filter
def localize_numbers_ckb(value):
    numbers = {
        "0": "٠",
        "1": "١",
        "2": "٢",
        "3": "٣",
        "4": "٤",
        "5": "٥",
        "6": "٦",
        "7": "٧",
        "8": "٨",
        "9": "٩",
    }

    for e, p in numbers.items():
        value = value.replace(e, p)
    
    return str(value)

@register.filter
def to_persian_digits(value):
    persian_digits = '۰۱۲۳۴۵۶۷۸۹'
    return ''.join(persian_digits[int(d)] if d.isdigit() else d for d in str(value))

@register.filter
def to_kurdish_digits(value):
    persian_digits = '٠١٢٣٤٥٦٧٨٩'
    return ''.join(persian_digits[int(d)] if d.isdigit() else d for d in str(value))
