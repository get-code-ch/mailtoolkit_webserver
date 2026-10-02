// Cloudflare Email Worker: forwards every mail received by Email Routing to
// the analysis server (POST /ingest), for hosts whose SMTP port 25 is
// blocked.
//
// Settings of the Worker:
//   INGEST_URL    variable, e.g. https://mtk.kite-project.net/ingest
//   INGEST_TOKEN  secret, the same value as MTK_INGEST_TOKEN on the server
//
// Email Routing: catch-all rule of the domain, action "Send to a Worker".
export default {
  async email(message, env) {
    const response = await fetch(env.INGEST_URL, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.INGEST_TOKEN}`,
        "Content-Type": "message/rfc822",
        "X-Envelope-From": message.from,
        "X-Envelope-To": message.to,
      },
      body: await new Response(message.raw).arrayBuffer(),
    });

    if (response.status === 404) {
      // Unknown or expired address: the sender gets a bounce.
      message.setReject("Unknown or expired address");
      return;
    }
    if (!response.ok) {
      // Other errors are temporary: let the delivery fail and be retried.
      throw new Error(`analysis server answered ${response.status}`);
    }
  },
};
