(function (global) {
  var TOKEN_KEY = "aauth_mm_token";
  var ROLE_KEY = "aauth_mm_role";

  global.AAuthAuth = {
    getToken: function () {
      return sessionStorage.getItem(TOKEN_KEY);
    },
    setSession: function (token, role) {
      sessionStorage.setItem(TOKEN_KEY, token != null ? token : "");
      sessionStorage.setItem(ROLE_KEY, role);
    },
    getRole: function () {
      return sessionStorage.getItem(ROLE_KEY);
    },
    clear: function () {
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(ROLE_KEY);
    },
    /** Redirect to login if role does not match. Token required only for role "user". */
    requireRole: function (role, loginPath) {
      loginPath = loginPath || "index.html";
      var r = global.AAuthAuth.getRole();
      if (r !== role) {
        global.location.href = loginPath;
        return false;
      }
      if (role === "user" && !global.AAuthAuth.getToken()) {
        global.location.href = loginPath;
        return false;
      }
      return true;
    },
  };
})(typeof window !== "undefined" ? window : globalThis);
