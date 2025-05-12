import base64

# Manually decode again the contained expression
inner_decoded = base64.b64decode('g3vbGHpbWRfpbWFvuZA==').decode('utf-8')

print(inner_decoded)
