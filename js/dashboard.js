
// ======================================
// LinkShield AI - Dashboard System
// ======================================

const HISTORY_KEY = "linkShieldHistory";

// Get saved scan history
function getScanHistory() {
    return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
}

// Update dashboard statistics
function updateDashboard() {

    const history = getScanHistory();

    const totalScans = history.length;

    const legitimateScans = history.filter(
        scan => scan.prediction === "Legitimate"
    ).length;

    const phishingScans = history.filter(
        scan => scan.prediction === "Phishing"
    ).length;

    const phishingRate = totalScans > 0
        ? ((phishingScans / totalScans) * 100).toFixed(1)
        : 0;

    document.getElementById("totalScans").textContent = totalScans;

    document.getElementById("legitimateScans").textContent =
        legitimateScans;

    document.getElementById("phishingScans").textContent =
        phishingScans;

    document.getElementById("phishingRate").textContent =
        phishingRate + "%";

    displayRecentScans(history);
}

// Display latest scans
function displayRecentScans(history) {

    const recentScans = document.getElementById("recentScans");

    recentScans.replaceChildren();

    if (history.length === 0) {
        recentScans.textContent = "No recent scans available.";
        return;
    }

    history.slice(0, 5).forEach(scan => {

        const card = document.createElement("div");

        const isPhishing = scan.prediction === "Phishing";

        card.className = "recent-scan-card " +
            (isPhishing ? "phishing-card" : "legitimate-card");

        const title = document.createElement("h3");
        title.textContent = scan.prediction;

        const url = document.createElement("p");
        url.textContent = scan.url;

        const risk = document.createElement("p");
        risk.textContent = "Risk: " + scan.risk;

        const date = document.createElement("p");
        date.textContent = scan.date;

        card.append(title, url, risk, date);

        recentScans.appendChild(card);

    });
}

// Load dashboard
updateDashboard();
