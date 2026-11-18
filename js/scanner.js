
const scannerForm = document.getElementById("scannerForm");
const urlInput = document.getElementById("urlInput");
const errorMessage = document.getElementById("errorMessage");

let resultContainer = document.getElementById("resultContainer");

if (!resultContainer) {
    resultContainer = document.createElement("div");
    resultContainer.id = "resultContainer";
    scannerForm.insertAdjacentElement("afterend", resultContainer);
}

// Load AI Model
let modelReady = false;

async function initializeAI() {
    try {
        modelReady = await LinkShieldModel.loadModel();

        if (modelReady) {
            console.log("LinkShield AI is Ready!");
        } else {
            console.error("AI Model could not be loaded.");
        }
    } catch (error) {
        console.error("AI Initialization Error:", error);
    }
}

initializeAI();

// Create an element safely
function createElement(tag, className, text) {
    const element = document.createElement(tag);

    if (className) {
        element.className = className;
    }

    if (text !== undefined) {
        element.textContent = text;
    }

    return element;
}

// Create probability bar
function createProbability(label, percentage, type) {
    const wrapper = createElement("div", "probability-item");

    const header = createElement("div", "probability-header");

    const name = createElement("span", "probability-label", label);
    const value = createElement(
        "span",
        "probability-value",
        percentage.toFixed(2) + "%"
    );

    header.append(name, value);

    const track = createElement("div", "progress-track");
    const fill = createElement("div", "progress-fill " + type);

    fill.style.width = Math.min(100, Math.max(0, percentage)) + "%";

    track.appendChild(fill);
    wrapper.append(header, track);

    return wrapper;
}

// Display scan result
function displayResult(result) {
    const isPhishing = result.prediction === "Phishing";

    const card = createElement(
        "section",
        "scan-result-card " + (isPhishing ? "danger-result" : "safe-result")
    );

    const top = createElement("div", "result-top");

    const icon = createElement(
        "div",
        "result-icon",
        isPhishing ? "!" : "✓"
    );

    const heading = createElement("div", "result-heading");

    heading.append(
        createElement(
            "p",
            "result-status",
            isPhishing ? "THREAT DETECTED" : "ANALYSIS COMPLETED"
        ),
        createElement(
            "h2",
            "result-title",
            isPhishing ? "Potential Phishing URL" : "Likely Legitimate URL"
        )
    );

    top.append(icon, heading);

    const risk = createElement("div", "risk-level");

    risk.append(
        createElement("span", "", "Risk Level"),
        createElement(
            "strong",
            isPhishing ? "risk-high" : "risk-low",
            result.risk
        )
    );

    const confidence = createElement("div", "confidence-box");

    confidence.append(
        createElement("span", "confidence-label", "Model Confidence"),
        createElement(
            "strong",
            "confidence-value",
            result.confidence.toFixed(2) + "%"
        )
    );

    const probabilities = createElement("div", "probabilities");

    probabilities.append(
        createProbability(
            "Phishing Probability",
            result.phishingProbability,
            "phishing-fill"
        ),
        createProbability(
            "Legitimate Probability",
            result.legitimateProbability,
            "legitimate-fill"
        )
    );

    const scannedURL = createElement("div", "scanned-url");

    scannedURL.append(
        createElement("span", "", "Scanned URL"),
        createElement("p", "", result.url)
    );

    const warning = createElement(
        "p",
        "result-warning",
        "This is an automated prediction, not a guarantee of website safety."
    );

    card.append(
        top,
        risk,
        confidence,
        probabilities,
        scannedURL,
        warning
    );

    resultContainer.replaceChildren(card);
}

// Handle Form Submission
scannerForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const url = urlInput.value.trim();

    errorMessage.textContent = "";
    resultContainer.replaceChildren();

    // Validate URL
    let parsedURL;

    try {
        parsedURL = new URL(url);

        if (!["http:", "https:"].includes(parsedURL.protocol)) {
            throw new Error("Invalid protocol");
        }
    } catch (error) {
        errorMessage.textContent =
            "Please enter a valid HTTP or HTTPS URL.";
        return;
    }

    // Check AI Model
    if (!modelReady) {
        errorMessage.textContent =
            "AI Model is not ready. Please refresh the page.";
        return;
    }

    try {
        // Use the original URL to keep features consistent with training
        const result = LinkShieldModel.predict(url);

console.log("AI Prediction:", result);

// Save scan to history
saveScan(result);

// Display result
displayResult(result);
    } catch (error) {
        errorMessage.textContent =
            error.message || "An error occurred during URL analysis.";

        console.error(error);
    }
});
// ======================================
// Interactive Analysis Modals
// ======================================

let lastScanResult = null;

const detailsModal = document.getElementById("detailsModal");
const modalTitle = document.getElementById("modalTitle");
const modalBody = document.getElementById("modalBody");
const closeModal = document.getElementById("closeModal");

// Save the latest scan result
const originalDisplayResult = displayResult;

displayResult = function(result) {
    lastScanResult = result;
    originalDisplayResult(result);
};

// Create detail row safely
function addDetailRow(label, value, className = "") {
    const row = createElement("div", "detail-item");

    const name = createElement("span", "", label);
    const result = createElement("strong", className, value);

    row.append(name, result);

    return row;
}

// Open modal
function openDetails(type) {

    if (!lastScanResult) {
        modalTitle.textContent = "No Scan Available";

        modalBody.replaceChildren(
            createElement(
                "p",
                "modal-empty",
                "Please scan a URL first to view its analysis details."
            )
        );

        detailsModal.classList.add("active");
        detailsModal.setAttribute("aria-hidden", "false");
        return;
    }

    const result = lastScanResult;
    const features = result.features;

    modalBody.replaceChildren();

    if (type === "url") {

        modalTitle.textContent = "URL Analysis";

        const featureNames = [
            "URL Length",
            "Domain Length",
            "Number of Dots",
            "Number of Hyphens",
            "HTTPS Enabled",
            "IP Address Used",
            "Suspicious Keywords",
            "Subdomains"
        ];

        const featureValues = [
            features[0] + " characters",
            features[1] + " characters",
            features[2],
            features[3],
            features[4] ? "Yes" : "No",
            features[5] ? "Yes" : "No",
            features[6],
            features[7]
        ];

        featureNames.forEach((name, index) => {
            modalBody.appendChild(
                addDetailRow(name, featureValues[index])
            );
        });

        modalBody.appendChild(
            createElement(
                "p",
                "detail-note",
                "These eight features are extracted from the scanned URL and used by the machine learning model."
            )
        );
    }

    else if (type === "ai") {

        modalTitle.textContent = "AI Detection";

        const isPhishing = result.prediction === "Phishing";

        modalBody.append(
            addDetailRow(
                "AI Prediction",
                result.prediction,
                isPhishing ? "detail-danger" : "detail-safe"
            ),
            addDetailRow(
                "Model Confidence",
                result.confidence.toFixed(2) + "%"
            ),
            addDetailRow(
                "Phishing Probability",
                result.phishingProbability.toFixed(2) + "%"
            ),
            addDetailRow(
                "Legitimate Probability",
                result.legitimateProbability.toFixed(2) + "%"
            ),
            addDetailRow(
                "Model Type",
                "Random Forest"
            )
        );

        modalBody.appendChild(
            createElement(
                "p",
                "detail-note",
                "The Random Forest model combines predictions from multiple decision trees to classify the URL."
            )
        );
    }

    else if (type === "risk") {

        modalTitle.textContent = "Risk Assessment";

        const isPhishing = result.prediction === "Phishing";

        modalBody.append(
            addDetailRow(
                "Risk Level",
                result.risk,
                isPhishing ? "detail-danger" : "detail-safe"
            ),
            addDetailRow(
                "Prediction",
                result.prediction
            )
        );

        const reasons = [];

        if (features[4] === 0) {
            reasons.push("The URL does not use HTTPS.");
        }

        if (features[5] === 1) {
            reasons.push("The hostname uses an IP address.");
        }

        if (features[6] > 0) {
            reasons.push(
                features[6] + " suspicious keyword(s) detected."
            );
        }

        if (features[7] > 2) {
            reasons.push(
                "The URL contains multiple subdomains."
            );
        }

        modalBody.appendChild(
            createElement("h3", "", "Risk Indicators")
        );

        if (reasons.length === 0) {
            modalBody.appendChild(
                createElement(
                    "p",
                    "detail-note detail-safe",
                    "No indicators from the selected feature checks were found."
                )
            );
        } else {
            reasons.forEach(reason => {
                modalBody.appendChild(
                    createElement(
                        "p",
                        "detail-note detail-warning",
                        "• " + reason
                    )
                );
            });
        }

        modalBody.appendChild(
            createElement(
                "p",
                "detail-note",
                "Risk classification is based on the Random Forest prediction. Individual indicators do not independently prove that a website is malicious."
            )
        );
    }

    detailsModal.classList.add("active");
    detailsModal.setAttribute("aria-hidden", "false");
}

// Handle card clicks
document.querySelectorAll("[data-detail]").forEach(card => {

    card.addEventListener("click", function() {
        openDetails(this.dataset.detail);
    });

});

// Close modal
function hideDetailsModal() {
    detailsModal.classList.remove("active");
    detailsModal.setAttribute("aria-hidden", "true");
}

closeModal.addEventListener("click", hideDetailsModal);

detailsModal.addEventListener("click", function(event) {
    if (event.target === detailsModal) {
        hideDetailsModal();
    }
});

document.addEventListener("keydown", function(event) {
    if (event.key === "Escape") {
        hideDetailsModal();
    }
});