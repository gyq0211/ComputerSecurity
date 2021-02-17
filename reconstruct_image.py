import base64
import imghdr


def rot13(message):
    PAIRS = dict(zip("nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM",
                     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    return "".join(PAIRS.get(c, c) for c in message)


st = open("evidence.txt", "r")
st = st.read()
st = rot13(st)
st = st[::-1]
lens = len(st)
missing_padding = 4 - len(st) % 4
if missing_padding:
    st += '=' * missing_padding
image_data = base64.b64decode(st)
image_type = imghdr.what('file_like_none.jpg', image_data)

filename = 'output.' + image_type
with open(filename, 'wb') as f:
    f.write(image_data)
f.close()
