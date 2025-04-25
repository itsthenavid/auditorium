import requests

def translate_text_libre(text, target_language="fa", source_language="en"):
    response = requests.post(
        "https://libretranslate.de/translate",
        data={
            "q": text,
            "source": source_language,
            "target": target_language,
            "format": "text"
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    if response.status_code == 200:
        return response.json().get("translatedText", text)

    print("Translation failed:", response.status_code, response.text)
    return text

translate_text_libre("Hello, world!", "fa")
