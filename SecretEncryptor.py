"""
SecretEncryptor - Cifrador de secretos con interfaz gráfica.

Cifra contraseñas, tokens u otros secretos para publicarlos en un endpoint o en
un archivo de configuración. La aplicación cliente los descifra con
SecretCrypto (Java o Kotlin).

Formato del valor cifrado:
  con prefijo:  "<algoritmo>:<Base64>"   por ejemplo "aes256gcm:3q2+7w..."
  sin prefijo:  "<Base64>"               el algoritmo se indica por separado

Requisito: pip install cryptography   (tkinter viene incluido con Python en Windows)
"""
import base64
import binascii
import hashlib
import hmac
import os
import tkinter as tk
from tkinter import ttk

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # cryptography < 43
    TripleDES = algorithms.TripleDES

# Ordenados de más seguro a menos seguro. El código es el prefijo del valor cifrado.
ALGORITHMS = [
    ("aes256gcm", "AES-256-GCM", "Muy alta", "Recomendado. Cifra y autentica en un paso. Android nativo."),
    ("chacha20poly1305", "ChaCha20-Poly1305", "Muy alta", "Equivalente a AES-GCM; rápido sin aceleración AES. Android 9+ (API 28)."),
    ("aes256cbc-hmac", "AES-256-CBC + HMAC-SHA256", "Alta", "Cifra y luego autentica. Máxima compatibilidad."),
    ("aes128gcm", "AES-128-GCM", "Alta", "Autenticado, con llave de 128 bits."),
    ("aes256cbc", "AES-256-CBC sin autenticación", "Media", "No detecta alteraciones del valor cifrado."),
    ("3des", "3DES-CBC", "Baja", "Obsoleto. Solo para sistemas antiguos que no soporten AES."),
    ("base64", "Base64 (sin cifrado)", "Nula", "Solo codifica. Cualquiera puede leer el valor."),
]
ALGORITHM_CODES = [code for code, *_ in ALGORITHMS]
ALGORITHM_NAMES = {code: name for code, name, *_ in ALGORITHMS}
INTEGRITY_ERROR = "Integridad no válida: el valor fue alterado o la llave no corresponde."
MISMATCH_ERROR = "No se pudo descifrar: la llave o el algoritmo no corresponden."


def deriveKey(masterKey: bytes, label: str) -> bytes:
    return hmac.new(masterKey, label.encode("utf-8"), hashlib.sha256).digest()


def parseMasterKey(masterKeyBase64: str) -> bytes:
    masterKey = base64.b64decode(masterKeyBase64.strip(), validate=True)
    if len(masterKey) != 32:
        raise ValueError("La llave maestra debe tener 32 bytes (Base64 de 44 caracteres).")
    return masterKey


def generateMasterKey() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


def generateToken() -> str:
    return os.urandom(32).hex()


def _aeadCipher(algorithm: str, masterKey: bytes):
    if algorithm == "aes256gcm":
        return AESGCM(deriveKey(masterKey, "aes256gcm"))
    if algorithm == "aes128gcm":
        return AESGCM(deriveKey(masterKey, "aes128gcm")[:16])
    return ChaCha20Poly1305(deriveKey(masterKey, "chacha20"))


def _cbcEncrypt(algo, key, ivSize, data):
    iv = os.urandom(ivSize)
    padder = padding.PKCS7(algo.block_size).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algo(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(padded) + enc.finalize()


def _cbcDecrypt(algo, key, ivSize, payload):
    dec = Cipher(algo(key), modes.CBC(payload[:ivSize])).decryptor()
    padded = dec.update(payload[ivSize:]) + dec.finalize()
    unpadder = padding.PKCS7(algo.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encryptSecret(plainText: str, masterKeyBase64: str, algorithm: str, includePrefix: bool = True) -> str:
    data = plainText.encode("utf-8")
    if algorithm == "base64":
        payload = data
    else:
        mk = parseMasterKey(masterKeyBase64)
        if algorithm == "aes256cbc-hmac":
            ivct = _cbcEncrypt(algorithms.AES, deriveKey(mk, "enc"), 16, data)
            payload = ivct + hmac.new(deriveKey(mk, "mac"), ivct, hashlib.sha256).digest()
        elif algorithm in ("aes256gcm", "aes128gcm", "chacha20poly1305"):
            nonce = os.urandom(12)
            payload = nonce + _aeadCipher(algorithm, mk).encrypt(nonce, data, None)
        elif algorithm == "aes256cbc":
            payload = _cbcEncrypt(algorithms.AES, deriveKey(mk, "aes256cbc"), 16, data)
        elif algorithm == "3des":
            payload = _cbcEncrypt(TripleDES, deriveKey(mk, "3des")[:24], 8, data)
        else:
            raise ValueError(f"Algoritmo no soportado: {algorithm}")
    encoded = base64.b64encode(payload).decode("ascii")
    return f"{algorithm}:{encoded}" if includePrefix else encoded


def resolveAlgorithm(value: str, algorithm: str = None) -> tuple:
    """Devuelve (algoritmo, Base64) a partir del prefijo o del algoritmo indicado."""
    value = value.strip()
    prefix, sep, body = value.partition(":")
    if sep:
        if prefix not in ALGORITHM_CODES:
            raise ValueError(f"Prefijo desconocido: {prefix}")
        if algorithm and algorithm != prefix:
            raise ValueError(f"El prefijo indica {ALGORITHM_NAMES[prefix]}, pero se eligió {ALGORITHM_NAMES[algorithm]}.")
        return prefix, body
    if not algorithm:
        raise ValueError("El valor no tiene prefijo: elige con qué algoritmo se cifró.")
    if algorithm not in ALGORITHM_CODES:
        raise ValueError(f"Algoritmo no soportado: {algorithm}")
    return algorithm, value


def decryptSecret(value: str, masterKeyBase64: str, algorithm: str = None) -> tuple:
    algorithm, body = resolveAlgorithm(value, algorithm)
    payload = base64.b64decode(body, validate=True)
    if algorithm == "base64":
        return algorithm, payload.decode("utf-8")
    mk = parseMasterKey(masterKeyBase64)
    if algorithm == "aes256cbc-hmac":
        ivct, tag = payload[:-32], payload[-32:]
        if not hmac.compare_digest(hmac.new(deriveKey(mk, "mac"), ivct, hashlib.sha256).digest(), tag):
            raise ValueError(INTEGRITY_ERROR)
        data = _cbcDecrypt(algorithms.AES, deriveKey(mk, "enc"), 16, ivct)
    elif algorithm in ("aes256gcm", "aes128gcm", "chacha20poly1305"):
        try:
            data = _aeadCipher(algorithm, mk).decrypt(payload[:12], payload[12:], None)
        except Exception:
            raise ValueError(INTEGRITY_ERROR)
    elif algorithm == "aes256cbc":
        try:
            data = _cbcDecrypt(algorithms.AES, deriveKey(mk, "aes256cbc"), 16, payload)
        except ValueError:
            raise ValueError(MISMATCH_ERROR)
    else:  # 3des
        try:
            data = _cbcDecrypt(TripleDES, deriveKey(mk, "3des")[:24], 8, payload)
        except ValueError:
            raise ValueError(MISMATCH_ERROR)
    try:
        return algorithm, data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(MISMATCH_ERROR)


# ---------- interfaz gráfica ----------
RED = "#C8161D"
GREEN = "#1E7B34"
AMBER = "#8A5A00"
MUTED = "#5B6470"
CLIPBOARD_CLEAR_MS = 60_000
LEVEL_COLOR = {"Muy alta": GREEN, "Alta": GREEN, "Media": AMBER, "Baja": RED, "Nula": RED}


class SecretEncryptorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.withdraw()  # oculta mientras se construye, para abrir ya centrada
        self.title("SecretEncryptor – Cifrador de secretos")
        self.minsize(600, 640)
        self.clipboardJob = None

        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("Muted.TLabel", foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Field.TLabel", font=("Segoe UI", 10, "bold"))

        root = ttk.Frame(self, padding=20)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(4, weight=1)

        ttk.Label(root, text="Cifrador de secretos", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(root, text="Cifra y verifica contraseñas, tokens u otros secretos.", style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 12))

        keyBox = ttk.Frame(root)
        keyBox.grid(row=2, column=0, sticky="ew")
        keyBox.columnconfigure(0, weight=1)
        ttk.Label(keyBox, text="Llave maestra (Base64)", style="Field.TLabel").grid(row=0, column=0, sticky="w")
        self.masterKeyVar = tk.StringVar()
        self.masterKeyEntry = ttk.Entry(keyBox, textvariable=self.masterKeyVar, show="•", font=("Segoe UI", 10))
        self.masterKeyEntry.grid(row=1, column=0, sticky="ew", pady=(2, 0))
        self.masterKeyStatus = tk.Label(keyBox, text="", width=20, anchor="w", font=("Segoe UI", 9))
        self.masterKeyStatus.grid(row=1, column=1, padx=(10, 0))
        keyButtons = ttk.Frame(keyBox)
        keyButtons.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Button(keyButtons, text="Generar llave nueva", command=self.generateKey).pack(side="left")
        ttk.Button(keyButtons, text="Copiar llave", command=lambda: self.copyText(self.masterKeyVar.get(), "Llave copiada")).pack(side="left", padx=8)
        self.showVar = tk.BooleanVar(value=False)
        ttk.Checkbutton(keyButtons, text="Mostrar lo escrito", variable=self.showVar, command=self.toggleShow).pack(side="left", padx=8)

        ttk.Separator(root).grid(row=3, column=0, sticky="ew", pady=14)

        tabs = ttk.Notebook(root)
        tabs.grid(row=4, column=0, sticky="nsew")
        self.buildEncryptTab(tabs)
        self.buildDecryptTab(tabs)
        self.buildGeneratorTab(tabs)

        self.statusLabel = tk.Label(root, text="Ingresa o genera la llave maestra.", anchor="w", fg=MUTED, font=("Segoe UI", 9))
        self.statusLabel.grid(row=5, column=0, sticky="ew", pady=(10, 0))

        for var in (self.masterKeyVar, self.valueVar, self.confirmVar, self.algorithmVar):
            var.trace_add("write", lambda *_: self.validate())
        self.protocol("WM_DELETE_WINDOW", self.onClose)
        self.masterKeyEntry.focus_set()
        self.validate()
        self.centerOnScreen(700, 720)
        self.deiconify()

    def centerOnScreen(self, width, height):
        self.update_idletasks()
        width = min(width, self.winfo_screenwidth())
        height = min(height, self.winfo_screenheight() - 80)
        x = (self.winfo_screenwidth() - width) // 2
        y = max((self.winfo_screenheight() - height) // 2 - 30, 0)
        self.geometry(f"{width}x{height}+{x}+{y}")

    # ---------- pestañas ----------
    def buildEncryptTab(self, tabs):
        tab = ttk.Frame(tabs, padding=14)
        tab.columnconfigure(0, weight=1)
        tabs.add(tab, text="Cifrar")

        ttk.Label(tab, text="Algoritmo (de más a menos seguro)", style="Field.TLabel").grid(row=0, column=0, sticky="w")
        self.algorithmLabels = [f"{name}  ·  Seguridad {level}" for _, name, level, _ in ALGORITHMS]
        self.algorithmVar = tk.StringVar(value=self.algorithmLabels[0])
        combo = ttk.Combobox(tab, textvariable=self.algorithmVar, values=self.algorithmLabels, state="readonly", font=("Segoe UI", 10))
        combo.grid(row=1, column=0, sticky="ew", pady=(2, 4))
        self.algorithmInfo = tk.Label(tab, text="", anchor="w", justify="left", wraplength=560, font=("Segoe UI", 9))
        self.algorithmInfo.grid(row=2, column=0, sticky="ew", pady=(0, 10))

        self.valueVar = tk.StringVar()
        self.confirmVar = tk.StringVar()
        self.valueEntry, self.valueStatus = self.addField(tab, 3, "Valor a cifrar", self.valueVar)
        self.confirmEntry, self.confirmStatus = self.addField(tab, 5, "Repite el valor", self.confirmVar)

        self.includePrefixVar = tk.BooleanVar(value=True)
        ttk.Checkbutton(tab, text="Incluir prefijo del algoritmo (por ejemplo, aes256gcm:...)", variable=self.includePrefixVar).grid(row=7, column=0, sticky="w")
        ttk.Label(tab, text="Desmárcalo si el algoritmo se indicará por separado, por ejemplo en un campo \"alg\" del endpoint.", style="Muted.TLabel", wraplength=560).grid(row=8, column=0, sticky="w", pady=(0, 10))

        buttons = ttk.Frame(tab)
        buttons.grid(row=9, column=0, sticky="w")
        self.encryptButton = ttk.Button(buttons, text="Cifrar", command=self.encrypt, state="disabled")
        self.encryptButton.pack(side="left")
        ttk.Button(buttons, text="Limpiar", command=self.clearEncrypt).pack(side="left", padx=8)

        ttk.Label(tab, text="Valor cifrado", style="Field.TLabel").grid(row=10, column=0, sticky="w", pady=(12, 4))
        self.resultText = tk.Text(tab, height=3, wrap="char", font=("Consolas", 10), state="disabled", relief="solid", borderwidth=1)
        self.resultText.grid(row=11, column=0, sticky="ew")
        self.copyButton = ttk.Button(tab, text="Copiar al portapapeles", command=lambda: self.copyText(self.readText(self.resultText), "Valor cifrado copiado"), state="disabled")
        self.copyButton.grid(row=12, column=0, sticky="w", pady=(8, 0))

    def buildDecryptTab(self, tabs):
        tab = ttk.Frame(tabs, padding=14)
        tab.columnconfigure(0, weight=1)
        tabs.add(tab, text="Descifrar / verificar")
        ttk.Label(tab, text="Valor cifrado", style="Field.TLabel").grid(row=0, column=0, sticky="w")
        self.cipherInput = tk.Text(tab, height=4, wrap="char", font=("Consolas", 10), relief="solid", borderwidth=1)
        self.cipherInput.grid(row=1, column=0, sticky="ew", pady=(2, 8))
        ttk.Label(tab, text="Algoritmo", style="Field.TLabel").grid(row=2, column=0, sticky="w")
        self.decryptLabels = ["Detectar por el prefijo"] + [name for _, name, *_ in ALGORITHMS]
        self.decryptAlgorithmVar = tk.StringVar(value=self.decryptLabels[0])
        ttk.Combobox(tab, textvariable=self.decryptAlgorithmVar, values=self.decryptLabels, state="readonly", font=("Segoe UI", 10)).grid(row=3, column=0, sticky="ew", pady=(2, 10))
        ttk.Button(tab, text="Descifrar", command=self.decrypt).grid(row=4, column=0, sticky="w")
        self.decryptInfo = tk.Label(tab, text="", anchor="w", justify="left", wraplength=560, font=("Segoe UI", 9))
        self.decryptInfo.grid(row=5, column=0, sticky="ew", pady=(10, 4))
        self.plainVar = tk.StringVar()
        self.plainEntry = ttk.Entry(tab, textvariable=self.plainVar, show="•", state="readonly", font=("Segoe UI", 10))
        self.plainEntry.grid(row=6, column=0, sticky="ew")
        ttk.Label(tab, text="El resultado se oculta; marca \"Mostrar lo escrito\" para verlo.", style="Muted.TLabel").grid(row=7, column=0, sticky="w", pady=(4, 0))

    def buildGeneratorTab(self, tabs):
        tab = ttk.Frame(tabs, padding=14)
        tab.columnconfigure(0, weight=1)
        tabs.add(tab, text="Generar llaves")
        ttk.Label(tab, text="Tipo", style="Field.TLabel").grid(row=0, column=0, sticky="w")
        self.generatorTypeVar = tk.StringVar(value="key")
        types = ttk.Frame(tab)
        types.grid(row=1, column=0, sticky="w", pady=(2, 8))
        ttk.Radiobutton(types, text="Llave maestra (Base64, 256 bits)", value="key", variable=self.generatorTypeVar).pack(side="left")
        ttk.Radiobutton(types, text="Token de acceso (hexadecimal, 256 bits)", value="token", variable=self.generatorTypeVar).pack(side="left", padx=12)
        ttk.Button(tab, text="Generar 5 propuestas", command=self.generateProposals).grid(row=2, column=0, sticky="w")
        self.proposalList = tk.Listbox(tab, height=5, font=("Consolas", 10), activestyle="none", exportselection=False)
        self.proposalList.grid(row=3, column=0, sticky="ew", pady=(10, 8))
        actions = ttk.Frame(tab)
        actions.grid(row=4, column=0, sticky="w")
        ttk.Button(actions, text="Usar como llave maestra", command=self.useProposal).pack(side="left")
        ttk.Button(actions, text="Copiar seleccionada", command=self.copyProposal).pack(side="left", padx=8)
        ttk.Label(tab, text="Cada propuesta se genera con el generador aleatorio criptográfico del sistema. Ninguna se guarda.", style="Muted.TLabel", wraplength=560).grid(row=5, column=0, sticky="w", pady=(10, 0))

    def generateProposals(self):
        self.proposalList.delete(0, "end")
        maker = generateMasterKey if self.generatorTypeVar.get() == "key" else generateToken
        for _ in range(5):
            self.proposalList.insert("end", maker())
        self.proposalList.selection_set(0)
        self.status("5 propuestas generadas. Elige una y guárdala en un lugar seguro.", AMBER)

    def selectedProposal(self):
        selection = self.proposalList.curselection()
        return self.proposalList.get(selection[0]) if selection else ""

    def useProposal(self):
        value = self.selectedProposal()
        if not value:
            self.status("Genera y selecciona una propuesta.", RED)
            return
        if self.generatorTypeVar.get() != "key":
            self.status("Un token no sirve como llave maestra. Elige el tipo \"Llave maestra\".", RED)
            return
        self.masterKeyVar.set(value)
        self.status("Llave maestra asignada desde la propuesta seleccionada.", GREEN)

    def copyProposal(self):
        value = self.selectedProposal()
        if not value:
            self.status("Genera y selecciona una propuesta.", RED)
            return
        self.copyText(value, "Propuesta copiada")

    # ---------- utilidades ----------
    def addField(self, parent, row, label, variable):
        ttk.Label(parent, text=label, style="Field.TLabel").grid(row=row, column=0, sticky="w")
        line = ttk.Frame(parent)
        line.grid(row=row + 1, column=0, sticky="ew", pady=(2, 10))
        line.columnconfigure(0, weight=1)
        entry = ttk.Entry(line, textvariable=variable, show="•", font=("Segoe UI", 10))
        entry.grid(row=0, column=0, sticky="ew")
        status = tk.Label(line, text="", width=18, anchor="w", font=("Segoe UI", 9))
        status.grid(row=0, column=1, padx=(10, 0))
        return entry, status

    def selectedAlgorithm(self):
        index = self.algorithmLabels.index(self.algorithmVar.get())
        return ALGORITHMS[index]

    def readText(self, widget):
        return widget.get("1.0", "end").strip()

    def writeText(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def status(self, text, color=MUTED):
        self.statusLabel.configure(text=text, fg=color)

    def keyIsValid(self):
        try:
            parseMasterKey(self.masterKeyVar.get())
            return True
        except (ValueError, binascii.Error):
            return False

    # ---------- acciones ----------
    def validate(self):
        key = self.masterKeyVar.get().strip()
        keyOk = self.keyIsValid()
        if not key:
            self.masterKeyStatus.configure(text="", fg=MUTED)
        elif keyOk:
            self.masterKeyStatus.configure(text="Llave válida", fg=GREEN)
        else:
            self.masterKeyStatus.configure(text=f"No válida ({len(key)}/44)", fg=RED)

        code, name, level, note = self.selectedAlgorithm()
        self.algorithmInfo.configure(text=f"Seguridad {level}. {note}", fg=LEVEL_COLOR[level])

        value, confirm = self.valueVar.get(), self.confirmVar.get()
        self.valueStatus.configure(text=f"{len(value)} caracteres" if value else "", fg=MUTED)
        if not confirm:
            self.confirmStatus.configure(text="", fg=MUTED)
        elif confirm == value:
            self.confirmStatus.configure(text="Coinciden", fg=GREEN)
        else:
            self.confirmStatus.configure(text="No coinciden", fg=RED)

        ready = (keyOk or code == "base64") and bool(value) and value == confirm
        self.encryptButton.configure(state="normal" if ready else "disabled")
        return ready

    def toggleShow(self):
        mask = "" if self.showVar.get() else "•"
        for entry in (self.masterKeyEntry, self.valueEntry, self.confirmEntry, self.plainEntry):
            entry.configure(show=mask)

    def generateKey(self):
        self.masterKeyVar.set(generateMasterKey())
        self.status("Llave nueva generada. Guárdala en un lugar seguro: sin ella no se puede descifrar.", AMBER)

    def encrypt(self):
        if not self.validate():
            self.status("Completa los campos: la llave debe ser válida y los valores deben coincidir.", RED)
            return
        code, name, level, _ = self.selectedAlgorithm()
        try:
            result = encryptSecret(self.valueVar.get(), self.masterKeyVar.get(), code, self.includePrefixVar.get())
        except Exception as error:  # noqa: BLE001
            self.status(f"Error al cifrar: {error}", RED)
            return
        self.writeText(self.resultText, result)
        self.copyButton.configure(state="normal")
        self.valueVar.set("")
        self.confirmVar.set("")
        note = "" if self.includePrefixVar.get() else f" Sin prefijo: indica el algoritmo {code} por separado."
        self.status(f"Valor cifrado con {name}.{note}", GREEN)

    def decrypt(self):
        value = self.readText(self.cipherInput)
        if not value:
            self.status("Pega un valor cifrado para verificarlo.", RED)
            return
        try:
            index = self.decryptLabels.index(self.decryptAlgorithmVar.get())
            chosen = ALGORITHM_CODES[index - 1] if index else None
            algorithm, plain = decryptSecret(value, self.masterKeyVar.get(), chosen)
        except binascii.Error:
            self.plainVar.set("")
            self.decryptInfo.configure(text="No se pudo descifrar: el valor no es Base64 válido o está incompleto.", fg=RED)
            self.status("Verificación fallida.", RED)
            return
        except ValueError as error:
            self.plainVar.set("")
            self.decryptInfo.configure(text=str(error), fg=RED)
            self.status("Verificación fallida.", RED)
            return
        except Exception as error:  # noqa: BLE001
            self.plainVar.set("")
            self.decryptInfo.configure(text=f"No se pudo descifrar: {error}", fg=RED)
            self.status("Verificación fallida.", RED)
            return
        name = ALGORITHM_NAMES[algorithm]
        self.plainVar.set(plain)
        self.decryptInfo.configure(text=f"Descifrado correctamente con {name}. Longitud: {len(plain)} caracteres.", fg=GREEN)
        self.status("Verificación correcta.", GREEN)

    def copyText(self, value, message):
        value = (value or "").strip()
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status(f"{message}. El portapapeles se limpiará en 60 segundos.", GREEN)
        if self.clipboardJob:
            self.after_cancel(self.clipboardJob)
        self.clipboardJob = self.after(CLIPBOARD_CLEAR_MS, self.clearClipboard)

    def clearClipboard(self):
        self.clipboard_clear()
        self.clipboardJob = None
        self.status("Portapapeles limpiado.")

    def clearEncrypt(self):
        self.valueVar.set("")
        self.confirmVar.set("")
        self.writeText(self.resultText, "")
        self.copyButton.configure(state="disabled")
        self.status("Campos limpiados.")

    def onClose(self):
        if self.clipboardJob:
            self.clipboard_clear()
        self.destroy()


if __name__ == "__main__":
    SecretEncryptorApp().mainloop()
