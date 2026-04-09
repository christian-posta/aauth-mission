(function (global) {
  function errMessage(r, body) {
    if (body && typeof body.detail === "string") return body.detail;
    if (body && Array.isArray(body.detail)) {
      return body.detail.map(function (x) {
        return x.msg || JSON.stringify(x);
      }).join("; ");
    }
    return r.statusText || "Request failed";
  }

  global.AAuthApi = {
    fetch: function (path, opts) {
      opts = opts || {};
      var h = new Headers(opts.headers || {});
      var t = global.AAuthAuth.getToken();
      if (t && !h.has("Authorization")) {
        h.set("Authorization", "Bearer " + t);
      }
      return fetch(path, Object.assign({}, opts, { headers: h }));
    },
    fetchJson: async function (path, opts) {
      var r = await global.AAuthApi.fetch(path, opts);
      var ct = r.headers.get("content-type") || "";
      var body = null;
      if (ct.indexOf("application/json") !== -1) {
        try {
          body = await r.json();
        } catch (e) {
          body = null;
        }
      }
      if (!r.ok) throw new Error(errMessage(r, body));
      return body;
    },
  };
})(typeof window !== "undefined" ? window : globalThis);
