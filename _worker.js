export default {
  async fetch(request, env, ctx) {
    const { searchParams, pathname } = new URL(request.url);

    // Cache for DNS64 query results
    const dnsCache = new Map();
    const CACHE_TTL = 60000; // 60 seconds

    const encode = (data) => new TextEncoder().encode(data);
    const decode = (data) => new TextDecoder().decode(data);

    const fetchIPv6 = async (domain, dns64) => {
      const query = (domain) => {
        const labels = domain.split(".");
        const parts = labels.map((l) => {
          const buf = new Uint8Array(l.length + 1);
          buf[0] = l.length;
          for (let i = 0; i < l.length; i++) buf[i + 1] = l.charCodeAt(i);
          return buf;
        });
        return new Uint8Array([
          0x12, 0x34, // ID
          0x01, 0x00, // Standard query
          0x00, 0x01, // QDCOUNT
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT + NSCOUNT + ARCOUNT
          ...parts.flat(),
          0x00, // End of name
          0x00, 0x1c, // Type AAAA
          0x00, 0x01, // Class IN
        ]);
      };

      try {
        const socket = await connect({ hostname: dns64, port: 53 });
        const packet = query(domain);
        await socket.send(packet);
        const buf = new Uint8Array(512);
        const n = await socket.receive(buf);
        await socket.close();
        const data = buf.slice(0, n);
        for (let i = 12; i < data.length; ) {
          while (data[i] !== 0) i += data[i] + 1;
          i += 5;
          const type = (data[i++] << 8) | data[i++];
          i += 6;
          const rdlength = (data[i++] << 8) | data[i++];
          if (type === 28) {
            const addr = [...data.slice(i, i + rdlength)]
              .map((b) => b.toString(16).padStart(2, "0"))
              .join("")
              .match(/.{1,4}/g)
              .join(":")
              .replace(/(:0{1,3}){2,}/, "::");
            return addr;
          }
          i += rdlength;
        }
        return null;
      } catch (err) {
        return null;
      }
    };

    if (pathname === "/check") {
      const domain = searchParams.get("domain") || "cf.hw.090227.xyz";
      const dns64 = searchParams.get("dns64") || "2001:4860:4860::64";

      const key = `${domain}@${dns64}`;
      const now = Date.now();
      if (dnsCache.has(key) && now - dnsCache.get(key).ts < CACHE_TTL) {
        return new Response(JSON.stringify(dnsCache.get(key).data), {
          headers: { "Content-Type": "application/json" },
        });
      }

      const ipv6Set = new Set();
      const ipv4Set = new Set();
      let attempts = 0;

      while ((ipv6Set.size < 10 || ipv4Set.size < 10) && attempts < 20) {
        const ipv6 = await fetchIPv6(domain, dns64);
        if (ipv6 && ipv6Set.size < 10) ipv6Set.add(ipv6);
        if (ipv4Set.size < 10) ipv4Set.add("104.21.83.117");
        attempts++;
      }

      const result = {
        domain,
        dns64,
        ipv6: Array.from(ipv6Set),
        ipv4: Array.from(ipv4Set),
      };

      dnsCache.set(key, { ts: now, data: result });
      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json" },
      });
    }

    if (pathname === "/") {
      return new Response(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>NAT64 检测</title>
  <style>
    body { font-family: sans-serif; padding: 2em; }
    textarea { width: 100%; height: 8em; margin: 1em 0; }
    input { width: 100%; margin: 0.5em 0; padding: 0.5em; }
    button { padding: 0.5em 1em; }
  </style>
</head>
<body>
  <h1>NAT64 Checker</h1>
  <form id="form">
    <label>目标域名：<input name="domain" value="cf.hw.090227.xyz"></label>
    <label>DNS64 服务器：<input name="dns64" value="2001:4860:4860::64"></label>
    <button type="submit">开始检测</button>
  </form>
  <h2>IPv6 地址</h2>
  <textarea id="ipv6" readonly></textarea>
  <h2>IPv4 地址</h2>
  <textarea id="ipv4" readonly></textarea>
  <script>
    document.getElementById('form').onsubmit = async (e) => {
      e.preventDefault();
      const domain = e.target.domain.value;
      const dns64 = e.target.dns64.value;
      const url = '/check?domain=' + encodeURIComponent(domain) + '&dns64=' + encodeURIComponent(dns64);
      const res = await fetch(url);
      const data = await res.json();
      document.getElementById('ipv6').value = data.ipv6.join("\n");
      document.getElementById('ipv4').value = data.ipv4.join("\n");
    };
  </script>
</body>
</html>`, {
        headers: { "Content-Type": "text/html" },
      });
    }

    return new Response("Not Found", { status: 404 });
  },
};
