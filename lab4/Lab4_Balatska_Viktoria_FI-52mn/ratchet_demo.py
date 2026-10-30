"""Навчальна модель Double Ratchet (спрощено, за специфікацією Signal) для демонстрації
Forward Secrecy, Post-Compromise Security та виявлення MITM через safety number.
Не є повною реалізацією протоколу (без X3DH/PQXDH, заголовків, пропущених повідомлень)."""
import copy, hashlib, hmac, os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

raw = lambda pub: pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def kdf_rk(rk, dh_out):
    out = HKDF(hashes.SHA256(), 64, rk, b'DR-root').derive(dh_out)
    return out[:32], out[32:]


def kdf_ck(ck):
    return hmac.new(ck, b'\x02', hashlib.sha256).digest(), hmac.new(ck, b'\x01', hashlib.sha256).digest()


class Party:
    def __init__(self, name, sk, dh=None, remote=None):
        self.name, self.rk, self.dhs, self.dhr = name, sk, dh or X25519PrivateKey.generate(), remote
        self.cks = self.ckr = None
        if remote is not None:                       # ініціатор одразу робить DH-крок
            self.rk, self.cks = kdf_rk(self.rk, self.dhs.exchange(remote))

    def send(self, text):
        if self.cks is None:                         # новий DH-крок перед відправкою
            self.dhs = X25519PrivateKey.generate()
            self.rk, self.cks = kdf_rk(self.rk, self.dhs.exchange(self.dhr))
        self.cks, mk = kdf_ck(self.cks)
        nonce = os.urandom(12)
        return raw(self.dhs.public_key()), nonce, AESGCM(mk).encrypt(nonce, text.encode(), None)

    def recv(self, msg):
        pub, nonce, ct = msg
        if self.dhr is None or pub != raw(self.dhr):  # співрозмовник змінив DH-ключ
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
            self.dhr = X25519PublicKey.from_public_bytes(pub)
            self.rk, self.ckr = kdf_rk(self.rk, self.dhs.exchange(self.dhr))
            self.cks = None
        self.ckr, mk = kdf_ck(self.ckr)
        return AESGCM(mk).decrypt(nonce, ct, None).decode()


# ---- Сеанс ----
shared = os.urandom(32)                               # спільний секрет після X3DH/PQXDH
bob_dh = X25519PrivateKey.generate()
alice = Party('Alice', shared, remote=bob_dh.public_key())
bob = Party('Bob', shared, dh=bob_dh)

log = []
def A(t): m = alice.send(t); bob.recv(m); log.append(('A', t, m))
def B(t): m = bob.send(t); alice.recv(m); log.append(('B', t, m))

A('A1: привіт'); A('A2: номер рахунку 1234')
# --- у цей момент зловмисник копіює повний стан пристрою Alice ---
stolen = copy.copy(alice)
A('A3: пароль від Wi-Fi')
B('B1: дякую'); B('B2: зустрінемось о 18:00')
A('A4: гаразд'); A('A5: нова адреса — вул. Садова, 5')

print('Стан Alice викрадено після повідомлення A2.\n')
print(f'{"Повідомлення":<38}{"Спроба зловмисника":<45}')
# Зловмисник пасивно перехоплює шифротексти і «проганяє» їх через викрадений стан
atk = copy.copy(stolen)
# відтворюємо: для вихідних повідомлень Alice атакувальник має лише ланцюг відправлення
send_ck = stolen.cks
for who, t, m in log:
    if who == 'A' and t.startswith(('A1', 'A2')):
        # маючи лише поточний ланцюговий ключ, атакувальник може рухатися тільки вперед
        try:
            AESGCM(kdf_ck(stolen.cks)[1]).decrypt(m[1], m[2], None); res = 'РОЗШИФРОВАНО'
        except Exception:
            res = 'не вдалося (ключі видалено, KDF односпрямована — FS)'
    elif who == 'A' and t.startswith('A3'):
        send_ck, mk = kdf_ck(send_ck)
        res = 'РОЗШИФРОВАНО: ' + AESGCM(mk).decrypt(m[1], m[2], None).decode()
    elif who == 'B':
        try: res = 'РОЗШИФРОВАНО: ' + atk.recv(m)
        except Exception: res = 'не вдалося'
    else:  # A4, A5 — після нового DH-кроку Alice: атакувальник знає rk і DH-ключ Bob (публічний),
           # але не новий закритий DH-ключ Alice; пробує вгадати його випадковим ключем
        guess = X25519PrivateKey.generate()
        _, ck = kdf_rk(atk.rk, guess.exchange(atk.dhr))
        try:
            AESGCM(kdf_ck(ck)[1]).decrypt(m[1], m[2], None); res = 'РОЗШИФРОВАНО'
        except Exception:
            res = 'не вдалося (новий DH-ключ Alice — PCS)'
    print(f'{t:<38}{res}')

# ---- Safety number / MITM ----
def safety(pub1, pub2):
    d = hashlib.sha512(b''.join(sorted([pub1, pub2]))).digest()
    n = int.from_bytes(d[:30], 'big')
    s = str(n).zfill(60)[:60]
    return ' '.join(s[i:i+5] for i in range(0, 60, 5))

ik_a, ik_b, ik_m = (raw(X25519PrivateKey.generate().public_key()) for _ in range(3))
print('\nSafety number без атаки:')
print('  Alice (IK_A+IK_B):', safety(ik_a, ik_b))
print('  Bob   (IK_A+IK_B):', safety(ik_a, ik_b))
print('Сервер підмінив ключі (MITM Mallory):')
print('  Alice (IK_A+IK_M):', safety(ik_a, ik_m))
print('  Bob   (IK_M+IK_B):', safety(ik_m, ik_b))
