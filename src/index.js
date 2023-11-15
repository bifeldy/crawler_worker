const requestHeadersToRemove = [
  'cf-connecting-ip',
  'x-forwarded-for',
  'x-real-ip'
];

export default {
  async fetch(req, env, ctx) {
    const { searchParams } = new URL(req.url);
    if (!searchParams.has('url')) {
      return Response.redirect('https://www.fansub.id', 301);
    }
    let url = searchParams.get('url');
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'http://' + url;
    }
    if (url.startsWith('http://')) {
      url = 'https://' + url.slice(7, url.length);
    }
    const fwd = new Request(url, req);
    for (const header of requestHeadersToRemove) {
      fwd.headers.delete(header);
    }
    const res = await fetch(fwd);
    if ([101, 204, 205, 304].includes(res.status)) {
      return new Response(null, res);
    } else {
      const { readable, writable } = new TransformStream();
      res.body.pipeTo(writable);
      return new Response(readable, res);
    }
  }
};
