(function () {
  function show(id, visible) {
    var el = document.getElementById(id);
    if (el) el.hidden = !visible;
  }

  fetch("/api/me", { credentials: "same-origin" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .catch(function () { return null; })
    .then(function (user) {
      var loggedIn = !!user;
      show("auth-login-google", !loggedIn);
      show("auth-login-github", !loggedIn);
      show("auth-logout", loggedIn);
      show("auth-user", loggedIn);
      if (loggedIn) {
        var name = document.getElementById("auth-user-name");
        // textContent, never innerHTML: the name comes from the identity provider.
        if (name) name.textContent = user.displayName || user.email || "";
      }
    });
})();
