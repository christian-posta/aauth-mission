(function (global) {
  var TOKEN_KEY = "aauth_portal_token";
  var ROLE_KEY = "aauth_portal_role";

  global.PortalAuth = {
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
    /** Redirect to login if not logged in as person (single role). */
    requireRole: function (loginPath) {
      loginPath = loginPath || "index.html";
      var r = global.PortalAuth.getRole();
      if (r !== "person" || !global.PortalAuth.getToken()) {
        global.location.href = loginPath;
        return false;
      }
      return true;
    },
  };
})(typeof window !== "undefined" ? window : globalThis);
