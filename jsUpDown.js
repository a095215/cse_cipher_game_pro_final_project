const token = localStorage.getItem("token");
    let username = "";

    async function upload() {
      const file = document.getElementById("fileInput").files[0];
      const buf = await file.arrayBuffer();
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
      const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, buf);

      const rawKey = await crypto.subtle.exportKey("raw", aesKey);
      const keyRes = await fetch("public.pem");
      const pem = await keyRes.text();
      const pemBody = pem.replace(/-----.*-----/g, '').replace(/\n/g, '');
      const binaryDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
      const rsaKey = await crypto.subtle.importKey(
        "spki", binaryDer.buffer, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]
      );
      const encryptedAESKey = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" }, rsaKey, rawKey
      );

      await fetch("http://localhost:5001/upload", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
        body: JSON.stringify({
          filename: file.name,
          ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
          iv: btoa(String.fromCharCode(...iv)),
          encryptedAESKey: btoa(String.fromCharCode(...new Uint8Array(encryptedAESKey))),
          token: token
        })
      });
      window.location.href = "updownload.html";
      alert("上傳完成！");
    }

    async function getFiles() {
      const res = await fetch("http://localhost:5001/list", {
        headers: { "Authorization": "Bearer " + token }
      });
      const files = await res.json();
      const select = document.getElementById("fileSelect");
      files.forEach(file => {
        const option = document.createElement("option");
        option.value = file.file_id;
        option.textContent = file.filename;
        select.appendChild(option);
      });
    }

    async function downloadSelected() {
      const fileId = document.getElementById("fileSelect").value;
      const res = await fetch("http://localhost:5001/download/" + fileId, {
        headers: { "Authorization": "Bearer " + token }
      });
      const data = await res.json();

      // 向 KMS 請求解密金鑰
      const usernamePayload = JSON.parse(atob(token.split(".")[1]));
      username = usernamePayload.sub;

      const keyRes = await fetch("http://localhost:5000/decrypt_key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username,
          encryptedAESKey: data.encryptedAESKey
        })
      });
      const keyData = await keyRes.json();
      if (keyData.status !== "success") {
        alert("金鑰解密失敗！");
        return;
      }

      const aesKey = await crypto.subtle.importKey(
        "raw", Uint8Array.from(atob(keyData.aesKey), c => c.charCodeAt(0)),
        "AES-GCM", false, ["decrypt"]
      );
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: Uint8Array.from(atob(data.iv), c => c.charCodeAt(0)) },
        aesKey,
        Uint8Array.from(atob(data.ciphertext), c => c.charCodeAt(0))
      );
      alert("解密內容如下：\n\n" + new TextDecoder().decode(decrypted));
    }

    getFiles();