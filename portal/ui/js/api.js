(function (global) {
  function errMessage(r, body) {
    if (body && typeof body.detail === "string") return body.detail;
    if (body && typeof body.error_description === "string") return body.error_description;
    if (body && Array.isArray(body.detail)) {
      return body.detail.map(function (x) { return x.msg || JSON.stringify(x); }).join("; ");
    }
    return r.statusText || "Request failed (" + r.status + ")";
  }

  function relativeTime(isoString) {
    if (!isoString) return "";
    var d = new Date(isoString);
    var now = new Date();
    var diffMs = d - now;
    var diffSec = Math.round(diffMs / 1000);
    if (Math.abs(diffSec) < 60) return diffSec >= 0 ? "in " + diffSec + "s" : Math.abs(diffSec) + "s ago";
    var diffMin = Math.round(diffSec / 60);
    if (Math.abs(diffMin) < 60) return diffMin >= 0 ? "in " + diffMin + "m" : Math.abs(diffMin) + "m ago";
    var diffHr = Math.round(diffMin / 60);
    return diffHr >= 0 ? "in " + diffHr + "h" : Math.abs(diffHr) + "h ago";
  }

  function copyToClipboard(text) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(function () {});
    }
  }

  global.PortalApi = {
    fetch: function (path, opts) {
      opts = opts || {};
      var h = new Headers(opts.headers || {});
      var t = global.PortalAuth.getToken();
      if (t && !h.has("Authorization")) {
        h.set("Authorization", "Bearer " + t);
      }
      return fetch(path, Object.assign({}, opts, { headers: h }));
    },
    fetchJson: async function (path, opts) {
      var r = await global.PortalApi.fetch(path, opts);
      var ct = r.headers.get("content-type") || "";
      var body = null;
      if (ct.indexOf("application/json") !== -1) {
        try { body = await r.json(); } catch (e) { body = null; }
      }
      if (!r.ok) throw new Error(errMessage(r, body));
      return body;
    },
    relativeTime: relativeTime,
    copyToClipboard: copyToClipboard,
  };

  global.relativeTime = relativeTime;
  global.copyToClipboard = copyToClipboard;
})(typeof window !== "undefined" ? window : globalThis);
