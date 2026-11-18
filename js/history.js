
// ======================================
// LinkShield AI - History System
// ======================================

const HISTORY_KEY = "linkShieldHistory";

const historyContainer = document.getElementById("historyContainer");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");
const historySearch = document.getElementById("historySearch");
const historyFilter = document.getElementById("historyFilter");

// Get saved history
function getScanHistory() {
    return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
}

// Save a new scan
function saveScan(result) {
    const history = getScanHistory();

    const scanRecord = {
        id: Date.now(),
        url: result.url,
        prediction: result.prediction,
        risk: result.risk,
        confidence: result.confidence,
        phishingProbability: result.phishingProbability,
        legitimateProbability: result.legitimateProbability,
        date: new Date().toLocaleString()
    };

    history.unshift(scanRecord);

    localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(history.slice(0, 100))
    );
}

// Display history
function displayHistory() {
    const history = getScanHistory();

    const searchValue = historySearch.value.trim().toLowerCase();
    const filterValue = historyFilter.value;

    const filteredHistory = history.filter(scan => {
        const matchesSearch = scan.url.toLowerCase().includes(searchValue);

        const matchesFilter =
            filterValue === "all" ||
            scan.prediction === filterValue;

        return matchesSearch && matchesFilter;
    });

    historyContainer.replaceChildren();

    if (filteredHistory.length === 0) {
        historyContainer.textContent = "No matching scan history found.";
        return;
    }

    filteredHistory.forEach(scan => {
        const card = document.createElement("div");

        const isPhishing = scan.prediction === "Phishing";

        card.className = "history-card " +
            (isPhishing ? "phishing-card" : "legitimate-card");

        const title = document.createElement("h3");
        title.textContent = scan.prediction;

        const url = document.createElement("p");
        url.textContent = scan.url;

        const risk = document.createElement("p");
        risk.textContent = "Risk Level: " + scan.risk;

        const confidence = document.createElement("p");
        confidence.textContent =
            "Confidence: " + Number(scan.confidence).toFixed(2) + "%";

        const date = document.createElement("p");
        date.textContent = scan.date;

        const deleteBtn = document.createElement("button");
        deleteBtn.textContent = "Delete";

        deleteBtn.addEventListener("click", () => {
            deleteScan(scan.id);
        });

        card.append(title, url, risk, confidence, date, deleteBtn);

        historyContainer.appendChild(card);
    });
}

// Delete one scan
function deleteScan(id) {
    const history = getScanHistory();

    const updatedHistory = history.filter(scan => scan.id !== id);

    localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(updatedHistory)
    );

    displayHistory();
}

// Clear all history
function clearHistory() {
    localStorage.removeItem(HISTORY_KEY);
    displayHistory();
}

// Event listeners
historySearch.addEventListener("input", displayHistory);
historyFilter.addEventListener("change", displayHistory);
clearHistoryBtn.addEventListener("click", clearHistory);

// Load history
displayHistory();
