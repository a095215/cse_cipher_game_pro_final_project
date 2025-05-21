from flask import Flask, request, jsonify
import jwt
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

with open("public.pem", "rb") as f:
    public_key = f.read()

# 模擬儲存結構
data_storage = {}

def verify_token():
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return None, "缺少 token"
    token = auth.split()[1]
    try:
        decoded = jwt.decode(token, public_key, algorithms=["RS256"], audience="data_server")
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