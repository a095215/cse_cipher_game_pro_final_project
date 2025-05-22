from flask import Flask, request, jsonify
import jwt
from flask_cors import CORS
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
CORS(app)

CA_CERT_PATH = "certs/ca.crt"
data_storage = {}

def load_and_verify_cert(username):
    # 載入 CA 根憑證
    ca_cert = x509.load_pem_x509_certificate(open(CA_CERT_PATH,"rb").read())
    # 載入使用者憑證
    user_cert_path = f"certs/{username}.crt"
    print(user_cert_path)
    user_cert = x509.load_pem_x509_certificate(open(user_cert_path,"rb").read())

    # 驗證這張憑證確實由 CA 簽發
    ca_cert.public_key().verify(
        user_cert.signature,
        user_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        user_cert.signature_hash_algorithm
    )
    # 通過後回傳裡面的公鑰
    return user_cert.public_key()

def verify_token():
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return None, "缺少 token"
    token = auth.split()[1]

    # 先無簽名解析出 sub（username）
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        username = unverified["sub"]
    except Exception:
        return None, "Token 格式錯誤"

    # 用憑證驗章
    try:
        public_key = load_and_verify_cert(username)
    except Exception as e:
        return None, f"憑證驗證失敗：{e}"

    # 用從憑證取得的公鑰驗 JWT
    try:
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience="data_server"
        )
        return decoded["sub"], None
    except jwt.ExpiredSignatureError:
        return None, "Token 已過期"
    except jwt.InvalidTokenError:
        return None, "Token 無效"

@app.route("/list", methods=["GET"])
def list_files():
    username, err = verify_token()
    if err: return jsonify({"status": "fail", "message": err}), 401
    result = []
    for fid, f in data_storage.items():
        if username in f["shared_keys"] and f["filename"].endswith(".txt"):
            result.append({"file_id": fid, "filename": f["filename"]})
    return jsonify(result)

@app.route("/download/<file_id>", methods=["GET"])
def download(file_id):
    username, err = verify_token()
    if err: return jsonify({"status": "fail", "message": err}), 401
    f = data_storage.get(file_id)
    if not f or username not in f["shared_keys"]:
        return jsonify({"status": "fail", "message": "未授權或找不到檔案"}), 403
    return jsonify({
        "file_id": file_id,
        "filename": f["filename"],
        "ciphertext": f["ciphertext"],
        "iv": f["iv"],
        "encryptedAESKey": f["shared_keys"][username]
    })

@app.route("/upload", methods=["POST"])
def upload():
    data = request.json
    username, err = verify_token()
    if err: return jsonify({"status": "fail", "message": err}), 401
    file_id = "file" + str(len(data_storage) + 1)
    data_storage[file_id] = {
        "owner": username,
        "filename": data["filename"],
        "ciphertext": data["ciphertext"],
        "iv": data["iv"],
        "shared_keys": {
            username: data["encryptedAESKey"]
        }
    }
    return jsonify({"status": "success", "file_id": file_id})

if __name__ == "__main__":
    app.run(port=5001)