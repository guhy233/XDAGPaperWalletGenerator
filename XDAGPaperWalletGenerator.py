import hashlib, ecdsa, base58, qrcode, textwrap
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from tkinter import messagebox
import ttkbootstrap as ttk


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


def generate_paperwallet(key_pair: tuple, file_name: str) -> None:
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


class XDAGPaperWalletGeneratorUI(ttk.Frame):
    
    def __init__(self, root, **kwargs) -> None:
        super().__init__(root, **kwargs)

        self.key_pair = None
        self.paper_wallet = None

        ttk.Label(root, text="Address", font=("", 16))\
            .grid(row=0, column=0, padx=5, pady=5)

        self.address_text = ttk.Entry(root, state="readonly", width=38)
        self.address_text.grid(row=1, column=0, padx=5, pady=5)

        ttk.Label(root, text="Private Key", font=("", 16))\
            .grid(row=2, column=0, padx=5, pady=5)

        ttk.Button(root, text="Generate", width=10, command=self.generate_key_pair_and_update_screen)\
            .grid(row=2, column=1, padx=5, pady=5)

        self.key_text = ttk.Entry(root, state="readonly", width=38)
        self.key_text.grid(row=3, column=0, padx=5, pady=5)

        ttk.Button(root, text="Save", width=10, command=self.save_as_paper_wallet)\
            .grid(row=3, column=1, padx=5, pady=5)


    def generate_key_pair_and_update_screen(self) -> None:
        self.key_pair = generate_key_pair()
        self.address_text.config(state="normal")
        self.address_text.delete(0, "end")
        self.address_text.insert(0, self.key_pair[2])
        self.address_text.config(state="readonly")
        self.key_text.config(state="normal")
        self.key_text.delete(0, "end")
        self.key_text.insert(0, self.key_pair[0])
        self.key_text.config(state="readonly")

    
    def save_as_paper_wallet(self):
        if self.key_pair == None:
            self.generate_key_pair_and_update_screen()
        generate_paperwallet(self.key_pair, "XDAG Paper Wallet.pdf")
        messagebox.showinfo(message="Save as ./XDAG Paper Wallet.pdf")
        




def main() -> None:
    ui = ttk.Window("XDAG Paper Wallet Generator")

    xdag_ui = XDAGPaperWalletGeneratorUI(ui)
    xdag_ui.mainloop()


if __name__ == "__main__":
    main()
