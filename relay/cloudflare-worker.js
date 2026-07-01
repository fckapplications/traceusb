export default {
  async fetch(request, env) {
    if (request.method === "GET") {
      return new Response("TraceUSB Discord relay is alive.\n", {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed\n", { status: 405 });
    }

    if (!env.DISCORD_WEBHOOK_URL) {
      return new Response("Relay is not configured\n", { status: 500 });
    }

    if (env.TRACEUSB_RELAY_TOKEN) {
      const suppliedToken = request.headers.get("X-TraceUSB-Relay-Token") || "";
      if (suppliedToken !== env.TRACEUSB_RELAY_TOKEN) {
        return new Response("Unauthorized\n", { status: 401 });
      }
    }

    const contentType = request.headers.get("content-type") || "application/json";
    const discordResponse = await fetch(env.DISCORD_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "content-type": contentType,
        "user-agent": "TraceUSB-Discord-Relay/1.0",
      },
      body: request.body,
    });

    const responseText = await discordResponse.text();
    if (!discordResponse.ok) {
      return new Response(responseText || "Discord delivery failed\n", {
        status: discordResponse.status,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    return new Response(responseText || "ok\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  },
};
