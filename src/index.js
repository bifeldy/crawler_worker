/**
 * CLOUDFLARE WORKER REVERSE PROXY - MULTI-LEVEL INTERCEPT
 * Modes: all, partial, true (default target), false
 */

const requestHeadersToRemove = [
  'cf-connecting-ip', 'x-forwarded-for', 'x-real-ip', 'cf-ray', 'cf-visitor', 'cf-ipcountry'
];

const staticBypass = [
  'googleusercontent.com', 'gstatic.com', 'googleapis.com', 'blogger.com', 'wp.com',
  'youtube.com', 'youtu.be', 'doubleclick.net', 'ggpht.com'
];

const getShouldBypass = (urlStr, targetHostname, mode) => {
  try {
    const url = new URL(urlStr);

    // 1. Mode 'all': Jangan bypass apapun (Intercept semuanya)
    if (mode === 'all') {
      return false;
    }

    // 2. Mode 'partial': Bypass hanya domain statis korporasi
    if (mode === 'partial') {
      return staticBypass.some(d => url.hostname.endsWith(d));
    }

    // 3. Mode 'true' (Default): Bypass semua yang bukan domain target
    if (mode === 'true') {
      // Selalu bypass korporasi juga di mode ini agar tidak pecah
      if (staticBypass.some(d => url.hostname.endsWith(d))) {
        return true;
      }

      return url.hostname !== targetHostname;
    }

    // 4. Mode 'false' atau lainnya: Bypass semuanya
    return true;
  } catch (e) {
    return false;
  }
};

const constructWorkerUrl = (workerOrigin, targetUrl, mode) => {
  const validModes = ['all', 'partial', 'true'];
  const interceptParam = validModes.includes(mode) ? `intercept=${mode}&` : '';
  return `${workerOrigin}/?${interceptParam}url=${encodeURIComponent(targetUrl)}`;
};

export default {
  async fetch(req, env, ctx) {
    const workerUrl = new URL(req.url);
    const intercept = workerUrl.searchParams.get('intercept'); // all, partial, true
    let targetUrlStr = workerUrl.searchParams.get('url');

    if (!targetUrlStr) {
      return Response.redirect('https://www.fansub.id', 301);
    }

    if (!targetUrlStr.startsWith('http')) {
      targetUrlStr = 'https://' + targetUrlStr;
    }

    const targetUrl = new URL(targetUrlStr);
    const targetHostname = targetUrl.hostname;

    const fwdRequest = new Request(targetUrl, req);
    requestHeadersToRemove.forEach(h => {
      fwdRequest.headers.delete(h);
    });

    const response = await fetch(fwdRequest);

    if ([101, 204, 205, 304].includes(response.status) || req.method === 'HEAD') {
      return new Response(null, response);
    }

    if (response.status === 468 || response.status === 403) {
      return new Response(response.body, response);
    }

    if ([301, 302, 307, 308].includes(response.status)) {
      const location = response.headers.get('Location');
      if (location) {
        const redirUrl = new URL(location, targetUrl.href).href;
        return Response.redirect(constructWorkerUrl(workerUrl.origin, redirUrl, intercept), response.status);
      }
    }

    const contentType = response.headers.get('content-type') || '';
    const newHeaders = new Headers(response.headers);
    newHeaders.set('Access-Control-Allow-Origin', '*');
    newHeaders.delete('content-security-policy');
    newHeaders.delete('x-frame-options');
    newHeaders.delete('x-content-type-options');
    newHeaders.set('Referrer-Policy', 'no-referrer-when-downgrade');

    if (contentType.includes('text/html')) {
      const genericHandler = new ElementHandler('', workerUrl.origin, targetUrl.origin, intercept, targetHostname);

      return new HTMLRewriter()
        .on('head', new ScriptInjector(workerUrl.origin, intercept, targetHostname))
        .on('a', new ElementHandler('href', workerUrl.origin, targetUrl.origin, intercept, targetHostname))
        .on('img', new ElementHandler('src', workerUrl.origin, targetUrl.origin, intercept, targetHostname))
        .on('script', new ElementHandler('src', workerUrl.origin, targetUrl.origin, intercept, targetHostname))
        .on('link', new ElementHandler('href', workerUrl.origin, targetUrl.origin, intercept, targetHostname))
        .on('iframe', new ElementHandler('src', workerUrl.origin, targetUrl.origin, intercept, targetHostname))
        .on('*', { element(el) { genericHandler.element(el); } })
        .transform(new Response(response.body, { status: response.status, headers: newHeaders }));
    }
    else if (contentType.includes('text/css')) {
      let cssText = await response.text();
      if (!cssText) {
        return new Response(null, response);
      }

      cssText = cssText.replace(/url\(['"]?([^'"]+)['"]?\)/g, (match, p1) => {
        if (p1.startsWith('data:') || p1.includes(workerUrl.origin)) {
          return match;
        }

        try {
          const absUrl = new URL(p1, targetUrl.href).href;
          if (getShouldBypass(absUrl, targetHostname, intercept)) {
            return `url("${absUrl}")`;
          }

          return `url("${constructWorkerUrl(workerUrl.origin, absUrl, intercept)}")`;
        } catch (e) {
          return match;
        }
      });

      return new Response(cssText, { status: response.status, headers: newHeaders });
    }
    else if (contentType.includes('javascript')) {
      let jsText = await response.text();
      if (!jsText) {
        return new Response(null, response);
      }

      const validModes = ['all', 'partial', 'true'];
      if (validModes.includes(intercept)) {
        const targetHostRegex = targetHostname.replace(/\./g, '\\.');
        const regex = new RegExp(`(?<!url=)https?://${targetHostRegex}`, 'g');
        const replacementPrefix = `${workerUrl.origin}/?intercept=${intercept}&url=`;
        jsText = jsText.replace(regex, `${replacementPrefix}https://${targetHostname}`);
      }

      return new Response(jsText, { status: response.status, headers: newHeaders });
    }

    return new Response(response.body, { status: response.status, headers: newHeaders });
  }
};

class ScriptInjector {
  constructor(workerOrigin, intercept, targetHostname) {
    this.workerOrigin = workerOrigin;
    this.intercept = intercept;
    this.targetHostname = targetHostname;
  }
  element(element) {
    element.prepend('<meta name="referrer" content="no-referrer-when-downgrade">', { html: true });

    const proxyJS = `(function() {
        const workerOrigin = "${this.workerOrigin}";
        const intercept = "${this.intercept || ''}";
        const targetHostname = "${this.targetHostname}";
        const staticBypass = ${JSON.stringify(staticBypass)};

        const rewrite = (url) => {
          if (!url || typeof url !== 'string' || url.startsWith('data:') || url.startsWith(workerOrigin) || url.startsWith('blob:')) {
            return url;
          }

          try {
            const abs = new URL(url, location.href);

            let shouldBypass = false;
            if (intercept === 'all') {
              shouldBypass = false;
            }
            else if (intercept === 'partial') {
              shouldBypass = staticBypass.some(d => abs.hostname.endsWith(d));
            }
            else if (intercept === 'true') {
              shouldBypass = staticBypass.some(d => abs.hostname.endsWith(d)) || abs.hostname !== targetHostname;
            }
            else shouldBypass = true;

            if (shouldBypass) {
              return abs.href;
            }

            return workerOrigin + "/?intercept=" + intercept + "&url=" + encodeURIComponent(abs.href);
          } catch(e) {
            return url;
          }
        };

        const originalFetch = window.fetch;
        window.fetch = (i, init) => (typeof i === 'string') ? originalFetch(rewrite(i), init) : originalFetch(i, init);

        const originalOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(m, url) {
          return originalOpen.apply(this, [m, rewrite(url), ...Array.from(arguments).slice(2)]);
        };
      })();`;
    element.prepend(`<script>${proxyJS}</script>`, { html: true });
  }
}

class ElementHandler {
  constructor(attr, workerOrigin, targetOrigin, intercept, targetHostname) {
    this.attr = attr;
    this.workerOrigin = workerOrigin;
    this.targetOrigin = targetOrigin;
    this.intercept = intercept;
    this.targetHostname = targetHostname;
  }
  element(element) {
    element.removeAttribute('integrity');
    if (this.attr) {
      let val = element.getAttribute(this.attr);
      if (val && !val.startsWith('data:') && !val.startsWith('javascript:') && !val.includes(this.workerOrigin)) {
        try {
          const absolute = new URL(val, this.targetOrigin).href;

          if (getShouldBypass(absolute, this.targetHostname, this.intercept)) {
            element.setAttribute(this.attr, absolute);
          }
          else {
            element.setAttribute(this.attr, constructWorkerUrl(this.workerOrigin, absolute, this.intercept));
          }
        } catch (e) { }
      }
    }

    const style = element.getAttribute('style');
    if (style && style.includes('url(')) {
      const newStyle = style.replace(/url\(['"]?([^'"]+)['"]?\)/g, (match, p1) => {
        if (p1.startsWith('data:') || p1.includes(this.workerOrigin)) {
          return match;
        }

        try {
          const absUrl = new URL(p1, this.targetOrigin).href;
          if (getShouldBypass(absUrl, this.targetHostname, this.intercept)) {
            return `url("${absUrl}")`;
          }

          return `url("${constructWorkerUrl(this.workerOrigin, absUrl, this.intercept)}")`;
        } catch (e) {
          return match;
        }
      });

      element.setAttribute('style', newStyle);
    }
  }
}