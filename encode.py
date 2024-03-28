import chardet

with open('requirements.txt', 'r', encoding='utf-16') as f:
    content = f.read()

with open('requirements.txt', 'w', encoding='utf-8') as f:
    f.write(content)

