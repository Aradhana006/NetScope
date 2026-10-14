(function () {
  "use strict";
  function loginUrlWithEmail(email) {
    var base = "/login";
    if (!email) return base;
    return base + "?email=" + encodeURIComponent(email.trim());
  }
  function prefillLoginEmail() {
    var params = new URLSearchParams(window.location.search);
    var email = params.get("email");
    var input = document.getElementById("email");
    if (email && input && !input.value) input.value = email;
  }
  function showError(msg) {
    var el = document.getElementById("auth-error");
    if (!el) return;
    el.textContent = msg;
    el.classList.remove("hidden");
  }
  function clearError() {
    var el = document.getElementById("auth-error");
    if (!el) return;
    el.textContent = "";
    el.classList.add("hidden");
  }
  function validatePassword(password) {
    if (!password || password.length < 8) {
      return "Password must be at least 8 characters.";
    }
    if (!/[A-Za-z]/.test(password)) {
      return "Password must include at least one letter.";
    }
    if (!/\d/.test(password)) {
      return "Password must include at least one number.";
    }
    return null;
  }
  async function post(url, body) {
    var r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    });
    var ct = (r.headers.get("content-type") || "").toLowerCase();
    var data = {};
    if (ct.indexOf("application/json") >= 0) {
      data = await r.json();
    } else {
      var text = await r.text();
      if (!r.ok) {
        throw new Error(
          r.status >= 500
            ? "Server error during sign in. Restart the app and try again."
            : "Unexpected server response. Check that python app.py is running the latest code."
        );
      }
      throw new Error("Unexpected server response.");
    }
    if (!r.ok) throw new Error(data.error || "Request failed");
    return data;
  }
  var login = document.getElementById("login-form");
  if (login) {
    login.addEventListener("submit", async function (e) {
      e.preventDefault();
      try {
        await post("/api/auth/login", {
          email: document.getElementById("email").value,
          password: document.getElementById("password").value,
        });
        window.location.href = "/dashboard";
      } catch (err) {
        showError(err.message);
      }
    });
  }
  var signup = document.getElementById("signup-form");
  if (signup) {
    signup.addEventListener("submit", async function (e) {
      e.preventDefault();
      clearError();
      var password = document.getElementById("password").value;
      var confirm = document.getElementById("password_confirm").value;
      var pwdErr = validatePassword(password);
      if (pwdErr) {
        showError(pwdErr);
        return;
      }
      if (password !== confirm) {
        showError("Passwords do not match.");
        return;
      }
      try {
        await post("/api/auth/register", {
          full_name: document.getElementById("full_name").value,
          email: document.getElementById("email").value,
          password: password,
        });
        window.location.href = "/dashboard";
      } catch (err) {
        showError(err.message);
        if (/already registered/i.test(err.message)) {
          var emailVal = document.getElementById("email").value;
          var link = document.getElementById("signup-login-link");
          if (link) link.href = loginUrlWithEmail(emailVal);
        }
      }
    });
  }
  document.addEventListener("DOMContentLoaded", function () {
    prefillLoginEmail();
    var signupLoginLink = document.getElementById("signup-login-link");
    if (signupLoginLink) {
      signupLoginLink.addEventListener("click", function () {
        var emailVal = document.getElementById("email");
        if (emailVal && emailVal.value.trim()) {
          signupLoginLink.href = loginUrlWithEmail(emailVal.value);
        }
      });
    }
  });
})();
