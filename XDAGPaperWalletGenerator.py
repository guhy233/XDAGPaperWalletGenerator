import hashlib, ecdsa, base58, qrcode, textwrap
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm


def generate_key_pair() -> tuple:
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()

    x = public_key.pubkey.point.x()
    y = public_key.pubkey.point.y()

    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    x_bin = x.to_bytes(32, 'big')
    compressed_pubkey = prefix + x_bin

    sha256_hash = hashlib.sha256(compressed_pubkey).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    pubkey_hash = ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(pubkey_hash).digest()).digest()[:4]
    address_bin = pubkey_hash + checksum
    address_str = base58.b58encode(address_bin).decode()
    return (private_key.to_string().hex(), public_key.to_string().hex(), address_str)

def creat_paperwallet(key_pair: tuple, file_name: str) -> None:
    pdf = canvas.Canvas(file_name)

    qr_address = qrcode.make(key_pair[2])
    qr_private = qrcode.make(key_pair[0])
    pdf.drawInlineImage(qr_address, 2.25*cm, 23*cm, 4.5*cm, 4.5*cm)
    pdf.drawInlineImage(qr_private, 2.25*cm, 18*cm, 4.5*cm, 4.5*cm)

    private_key_str = textwrap.fill(key_pair[0], width=33)
    private_key_obj = pdf.beginText(8*cm, 20*cm)
    for line in private_key_str.splitlines(True):
        private_key_obj.textLine(line.rstrip())

    pdf.setFont("Courier", 16)
    pdf.drawString(8*cm, 26*cm, "XDAG Address:")
    pdf.drawString(8*cm, 21*cm, "Private Key:")
    pdf.drawString(8*cm, 25*cm, key_pair[2])
    pdf.drawText(private_key_obj)

    pdf.setDash([2, 2])
    pdf.line(cm, 22.75*cm, 20*cm, 22.75*cm)

    pdf.save()


if __name__ == "__main__":
    key_pair = generate_key_pair()
    print(key_pair[0])
    print(key_pair[1])
    print(key_pair[2])
    creat_paperwallet(key_pair, "paper wallet.pdf")
