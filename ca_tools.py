import os
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

CERT_DIR = "certs"
KEY_DIR = "kms_keys"

# 確保目錄存在，並檢查同名檔案衝突

def ensure_directory(path):
    if os.path.exists(path) and not os.path.isdir(path):
        raise Exception(f"'{path}' 已存在，且不是資料夾，請先移除同名檔案！")
    os.makedirs(path, exist_ok=True)

ensure_directory(CERT_DIR)
ensure_directory(KEY_DIR)

CA_KEY_PATH = os.path.join(CERT_DIR, "ca.key")
CA_CERT_PATH = os.path.join(CERT_DIR, "ca.crt")


def init_ca():
    """
    建立 CA 私鑰與根憑證
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MyMiniCA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    # 寫入 CA 私鑰與憑證
    with open(CA_KEY_PATH, "wb") as f:
        f.write(ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    with open(CA_CERT_PATH, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print("已建立 CA 私鑰與根憑證：", CA_KEY_PATH, CA_CERT_PATH)


def sign_user(username):
    """
    為使用者簽發憑證與私鑰
    """
    if not os.path.exists(CA_KEY_PATH) or not os.path.exists(CA_CERT_PATH):
        print("尚未建立 CA，請先執行 init_ca")
        return
    # 載入 CA 金鑰與憑證
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    # 產生使用者私鑰
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    user_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(user_name)
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    # 寫入檔案
    cert_path = os.path.join(CERT_DIR, f"{username}.crt")
    key_path = os.path.join(KEY_DIR, f"{username}.key")
    with open(cert_path, "wb") as f:
        f.write(user_cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(user_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    print(f"已為 {username} 建立私鑰與憑證：{key_path}, {cert_path}")


def export_spki(username):
    """
    從使用者憑證抽出 SPKI 格式公鑰並輸出到 public.pem
    """
    cert_path = os.path.join(CERT_DIR, f"{username}.crt")
    if not os.path.exists(cert_path):
        print(f"找不到 {cert_path}，請先 sign {username}")
        return
    cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
    pubkey_pem = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public.pem", "wb") as f:
        f.write(pubkey_pem)
    print(f"已匯出 {username} 的 SPKI 公鑰到 public.pem")

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="init_ca":
        init_ca()
    elif len(sys.argv)==3 and sys.argv[1]=="sign":
        sign_user(sys.argv[2])
    elif len(sys.argv)==3 and sys.argv[1]=="export_spki":
        export_spki(sys.argv[2])
    else:
        print("用法:\n  python ca_tools.py init_ca\n  python ca_tools.py sign <username>\n  python ca_tools.py export_spki <username>")
