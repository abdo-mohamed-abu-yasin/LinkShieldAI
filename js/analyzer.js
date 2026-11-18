
function extractURLFeatures(input) {

    let url;

    try {
        url = new URL(input);
    } catch {
        throw new Error("Invalid URL");
    }

    const hostname = url.hostname;
    const fullURL = url.href;

    const suspiciousKeywords = [
        "login",
        "verify",
        "account",
        "secure",
        "update",
        "password",
        "bank",
        "signin",
        "confirm"
    ];

    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;

    const features = {

        urlLength: fullURL.length,

        domainLength: hostname.length,

        dots: (fullURL.match(/\./g) || []).length,

        hyphens: (fullURL.match(/-/g) || []).length,

        hasHTTPS: url.protocol === "https:" ? 1 : 0,

        hasIP: ipPattern.test(hostname) ? 1 : 0,

        suspiciousKeywords:
            suspiciousKeywords.filter(keyword =>
                fullURL.toLowerCase().includes(keyword)
            ).length,

        subdomains:
            Math.max(0, hostname.split(".").length - 2)

    };

    return features;
}
