// Deployment settings for the browser client.

// The relay (relay/ in this repo). It must list this site's origin in its
// RELAY_ALLOWED_ORIGINS setting, e.g. https://share.nlpdf.site.
export const RELAY_URL = "https://relay.nlpdf.site";

// STUN servers WebRTC uses to find each browser's public address. There is
// no TURN server: when a direct connection can't be made, the transfer goes
// through the relay above instead.
export const ICE_SERVERS = [
  { urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"] },
];
