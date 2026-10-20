/** Debug exwall binary built for the musl target set in `.cargo/config.toml`. */
export const debugBinaryPath = "target/x86_64-unknown-linux-musl/debug/exwall";

/** Public names resolve only to peer namespace fixtures; there is no internet route. */
export const fixtureHosts = [
    "github.com",
    "api.github.com",
    "ipinfo.io",
    "httpbin.org",
    "pie.dev",
    "raw.githubusercontent.com",
    "esamatti.fi",
    "www.esamatti.fi",
    "example.com",
    "ftp.ubuntu-tw.org",
    "dns.google",
    "cloudflare-dns.com",
    "chatgpt.com",
    "openai.com",
    "api.openai.com",
    "cdn.chatgpt.com",
    "pathname.test",
];
