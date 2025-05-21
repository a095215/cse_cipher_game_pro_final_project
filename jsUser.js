let token = null;
    let username = "";

    async function login() {
      username = document.getElementById("username").value;
      const res = await fetch("http://localhost:5000/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username,
          password: document.getElementById("password").value,
          otp: document.getElementById("otp").value
        })
      });
      const json = await res.json();
      if (json.status === "need_otp") {
        alert("請查看 Terminal 顯示的 OTP 並輸入！");
        return;
      }
      if (json.status !== "success") {
        alert("登入失敗: " + json.message);
        return;
      }
      token = json.token;
      localStorage.setItem("token", token);
      localStorage.setItem("username", username);
      alert("登入成功！");
      document.getElementById("password").value = "";
      document.getElementById("otp").value = "";
      window.location.href = "updownload.html";
    }