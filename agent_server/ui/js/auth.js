(function (global) {
  var TOKEN_KEY = "aauth_as_token";
  var ROLE_KEY = "aauth_as_role";

  global.ASAuth = {
    getToken: function () {
      return sessionStorage.getItem(TOKEN_KEY) || "";
    },
    setSession: function (token, role) {
      sessionStorage.setItem(TOKEN_KEY, token != null ? token : "");
      sessionStorage.setItem(ROLE_KEY, role || "person");
    },
    getRole: function () {
      return sessionStorage.getItem(ROLE_KEY);
    },
    clear: function () {
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(ROLE_KEY);
    },
    requireRole: function (role, loginPath) {
      loginPath = loginPath || "index.html";
      var r = global.ASAuth.getRole();
      if (r !== role) {
        global.location.href = loginPath;
        return false;
      }
      return true;
    },
  };
})(typeof window !== "undefined" ? window : globalThis);
