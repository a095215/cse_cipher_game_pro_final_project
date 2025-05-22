const token = localStorage.getItem("token");
let username = "";


async function upload() {
  if (!token) {
    Swal.fire({
      icon: 'error',
      title: '未授權',
      text: '請先登入才能瀏覽檔案列表'
    });
    window.location.href = "login.html"; // 替換為你的登入頁面
  }
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
  
  const spinner = document.getElementById("uploadSpinner");
        spinner.classList.remove("d-none");

        // 模擬上傳
        setTimeout(() => {
            spinner.classList.add("d-none");

            Swal.fire({
                icon: 'success',
                title: '檔案上傳成功！',
                confirmButtonText: '確認'
            });
            getFiles();
        }

            , 1500);

    
  
}

async function getFiles() {
  if (!token) {
    Swal.fire({
      icon: 'error',
      title: '未授權',
      text: '請先登入才能瀏覽檔案列表'
    });
    window.location.href = "login.html"; // 替換為你的登入頁面
  }
  console.log(token)
  const res = await fetch("http://localhost:5001/list", {
    headers: { "Authorization": "Bearer " + token }
  });
  const files = await res.json();
  console.log(files)
  const select = document.getElementById("fileSelect");
  select.innerHTML = "";
  files.forEach(file => {
    const option = document.createElement("option");
    option.value = file.file_id;
    option.textContent = file.filename;
    select.appendChild(option);
  });
}

async function downloadSelected() {
  if (!token) {
    Swal.fire({
      icon: 'error',
      title: '未授權',
      text: '請先登入才能瀏覽檔案列表'
    });
    window.location.href = "login.html"; // 替換為你的登入頁面
  }
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