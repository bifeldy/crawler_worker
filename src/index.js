
export default {
  async fetch(req, env, ctx) {
    console.log('Request', req);
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
    let { readable, writable } = new TransformStream();
    const fwd = new Request(url, req);
    const res = await fetch(fwd);
    res.body.pipeTo(writable);
    return new Response(readable, res);
  }
};
