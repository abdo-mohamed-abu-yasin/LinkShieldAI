
// ======================================
// LinkShield AI - Random Forest Model
// ======================================

window.LinkShieldModel = (function () {

    let model = null;

    // Load trained model
    async function loadModel() {
        try {
            const response = await fetch("ml/model.json");

            if (!response.ok) {
                throw new Error("Could not load model.json");
            }

            model = await response.json();

            console.log("AI Model Loaded Successfully");
            console.log("Model Classes:", model.classes);
            console.log("Model Features:", model.feature_names);

            return true;

        } catch (error) {
            console.error("Model Loading Error:", error);
            return false;
        }
    }

    // Extract URL Features
 
function extractFeatures(inputURL) {

    const parsedURL = new URL(inputURL);
    const hostname = parsedURL.hostname;
    const fullURL = inputURL;

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

    const keywordCount = suspiciousKeywords.filter(
        keyword => fullURL.toLowerCase().includes(keyword)
    ).length;

    const hasIP = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);

    return [
        fullURL.length,
        hostname.length,
        (fullURL.match(/\./g) || []).length,
        (fullURL.match(/-/g) || []).length,
        Number(parsedURL.protocol === "https:"),
        Number(hasIP),
        keywordCount,
        Math.max(0, hostname.split(".").length - 2)
    ];
}


    // Predict One Decision Tree
    function predictTree(tree, features) {

        let node = tree;

        while (node.probabilities === undefined) {

            if (features[node.feature] <= node.threshold) {
                node = node.left;
            } else {
                node = node.right;
            }
        }

        return node.probabilities;
    }

    // Random Forest Prediction
    function predict(inputURL) {

        if (!model) {
            throw new Error("AI Model is not loaded");
        }

        const features = extractFeatures(inputURL);

        const phishingIndex = model.classes.indexOf(0);
        const legitimateIndex = model.classes.indexOf(1);

        if (phishingIndex === -1 || legitimateIndex === -1) {
            throw new Error("Unexpected model class labels");
        }

        let phishingProbability = 0;
        let legitimateProbability = 0;

        model.trees.forEach(tree => {

            const probabilities = predictTree(tree, features);

            phishingProbability += probabilities[phishingIndex];
            legitimateProbability += probabilities[legitimateIndex];

        });

        phishingProbability /= model.trees.length;
        legitimateProbability /= model.trees.length;

        const isPhishing = phishingProbability >= legitimateProbability;

        const result = {
            url: inputURL,
            prediction: isPhishing ? "Phishing" : "Legitimate",
            risk: isPhishing ? "High Risk" : "Low Risk",
            confidence: Math.max(
                phishingProbability,
                legitimateProbability
            ) * 100,
            phishingProbability: phishingProbability * 100,
            legitimateProbability: legitimateProbability * 100,
            features: features
        };

        console.log("Extracted Features:", features);
        console.log("Prediction Result:", result);

        return result;
    }

    return {
        loadModel,
        extractFeatures,
        predict
    };

})();
