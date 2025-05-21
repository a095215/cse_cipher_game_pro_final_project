from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import jwt, base64, datetime
from flask_cors import CORS
import random

app = Flask(__name__)
CORS(app)

# 模擬使用者資料
users = {
    "alice": {
        "password": "pw123",
        "otp": None,
        "private_key": rsa.generate_private_key(public_exponent=65537, key_size=2048)
    }
}

@app.route("/auth", methods=["POST"])
def auth():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    otp = data.get("otp")
    user = users.get(username)
    if not user or user["password"] != password:
        return jsonify({"status": "fail", "message": "使用者不存在或密碼錯誤"}), 401

    # 如果 otp 尚未產生，先產生後顯示
    if user["otp"] is None:
        user["otp"] = str(random.randint(100000, 999999))
        print(f"[2FA] 使用者 {username} 的 OTP 為: {user['otp']}")
        return jsonify({"status": "need_otp", "message": "請輸入 OTP"})

    # 驗證 OTP
    if otp != user["otp"]:
        return jsonify({"status": "fail", "message": "OTP 錯誤"}), 401

    # 驗證成功後清除 OTP 並發 token
    user["otp"] = None
    # 從 kms_keys/alice.key 載入私鑰（對應 certs/alice.crt）
    with open("kms_keys/alice.key","rb") as f:
       alice_priv = serialization.load_pem_private_key(f.read(), password=None)
    token = jwt.encode({
        "sub": username,
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=30),
        "iss": "kms.local",
        "aud": "data_server"
    }, alice_priv, algorithm="RS256")
    return jsonify({"status": "success", "token": token})

@app.route("/decrypt_key", methods=["POST"])
def decrypt_key():
    data = request.json
    username = data.get("username")
    enc_key_b64 = data.get("encryptedAESKey")
    key_path = f"kms_keys/{username}.key"
    try:
       with open(key_path, "rb") as f:
           priv = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
         return jsonify({"status": "fail", "message": "未知使用者或私鑰不存在"}), 401
    try:
        decrypted = priv.decrypt(
            base64.b64decode(enc_key_b64),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return jsonify({"status": "success", "aesKey": base64.b64encode(decrypted).decode()})
    except Exception as e:
        return jsonify({"status": "fail", "message": str(e)}), 400

if __name__ == "__main__":
    app.run(port=5000)