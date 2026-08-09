// ============================================================
// GLOBAL SETTINGS
// ============================================================

const MAX_MESSAGE_LENGTH = 5000;


// ============================================================
// ELEMENT REFERENCES
// ============================================================

const messageInput = document.getElementById("message");
const characterCount = document.getElementById("character-count");
const analyzeButton = document.querySelector(".analyze-button");


// ============================================================
// HTML ESCAPE HELPER
// ============================================================

function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


// ============================================================
// ANALYZE MESSAGE
// ============================================================

async function analyzeMessage() {

    const message = messageInput.value.trim();

    const result =
        document.getElementById("result");

    const loading =
        document.getElementById("loading");


    // --------------------------------------------------------
    // Empty input
    // --------------------------------------------------------

    if (!message) {

        result.innerHTML = `
            <div class="result-card">
                <p>Please enter a message first.</p>
            </div>
        `;

        return;
    }


    // --------------------------------------------------------
    // Frontend length validation
    // --------------------------------------------------------

    if (message.length > MAX_MESSAGE_LENGTH) {

        result.innerHTML = `
            <div class="result-card">
                <p>
                    Message is too long.
                    Please keep it under ${MAX_MESSAGE_LENGTH} characters.
                </p>
            </div>
        `;

        return;
    }


    // --------------------------------------------------------
    // Disable button while analyzing
    // --------------------------------------------------------

    analyzeButton.disabled = true;
    analyzeButton.textContent = "Analyzing...";

    loading.textContent = "Analyzing message...";
    result.innerHTML = "";


    try {

        const response = await fetch("/analyze", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                message: message
            })
        });


        const data = await response.json();

        loading.textContent = "";


        // ----------------------------------------------------
        // Backend error
        // ----------------------------------------------------

        if (!response.ok) {

            result.innerHTML = `
                <div class="result-card">
                    <p>
                        ${escapeHTML(
                            data.error || "Unable to analyze message."
                        )}
                    </p>
                </div>
            `;

            return;
        }


        // ----------------------------------------------------
        // Determine CSS class
        // ----------------------------------------------------

        let riskClass = "low";

        if (data.risk_level === "HIGH RISK") {

            riskClass = "high";

        } else if (data.risk_level === "MEDIUM RISK") {

            riskClass = "medium";
        }


        // ----------------------------------------------------
        // Build signals
        // ----------------------------------------------------

        let signalsHTML = "";

        if (data.signals && data.signals.length > 0) {

            data.signals.forEach(signal => {

                signalsHTML += `
                    <li class="signal-item">

                        <strong>
                            ${escapeHTML(signal.category)}
                        </strong>

                        <p>
                            ${escapeHTML(signal.description)}
                        </p>

                        <small>
                            Evidence:
                            <b>
                                ${escapeHTML(signal.evidence)}
                            </b>
                        </small>

                    </li>
                `;
            });

        } else {

            signalsHTML = `
                <li class="no-signal">
                    No major warning signals were detected.
                </li>
            `;
        }


        // ----------------------------------------------------
        // Display result
        // ----------------------------------------------------

        const score = Math.min(
            Math.max(Number(data.risk_score) || 0, 0),
            100
        );


        result.innerHTML = `

            <div class="result-card ${riskClass}">

                <div class="risk-header">

                    <div>

                        <span class="risk-label">
                            Assessment
                        </span>

                        <h2>
                            ${escapeHTML(data.risk_level)}
                        </h2>

                    </div>


                    <div class="score-circle">

                        <span>
                            ${score}
                        </span>

                        <small>
                            / 100
                        </small>

                    </div>

                </div>


                <div class="risk-meter">

                    <div
                        class="risk-meter-fill"
                        style="width: ${score}%"
                    ></div>

                </div>


                <h3>
                    Detected Signals
                </h3>


                <ul>
                    ${signalsHTML}
                </ul>


                <div class="recommendation">

                    <h3>
                        Recommendation
                    </h3>

                    <p>
                        ${escapeHTML(data.recommendation)}
                    </p>

                </div>

            </div>
        `;


        // ----------------------------------------------------
        // Refresh history
        // ----------------------------------------------------

        await loadHistory();


    } catch (error) {

        loading.textContent = "";

        result.innerHTML = `
            <div class="result-card">
                <p>
                    Something went wrong while connecting
                    to the analysis server.
                </p>
            </div>
        `;

    } finally {

        // ----------------------------------------------------
        // Re-enable button
        // ----------------------------------------------------

        analyzeButton.disabled = false;
        analyzeButton.textContent = "Analyze Message";
    }
}


// ============================================================
// LOAD SCAN HISTORY
// ============================================================

async function loadHistory() {

    const historyContainer =
        document.getElementById("history");


    try {

        const response =
            await fetch("/history");


        const data =
            await response.json();


        if (!response.ok) {

            historyContainer.innerHTML = `
                <div class="history-empty">
                    <p>
                        Unable to load scan history.
                    </p>
                </div>
            `;

            return;
        }


        const scans =
            data.scans || [];


        // ----------------------------------------------------
        // No history
        // ----------------------------------------------------

        if (scans.length === 0) {

            historyContainer.innerHTML = `
                <div class="history-empty">

                    <div class="history-empty-mark">
                        ···
                    </div>

                    <p>
                        Your recent scans will appear here.
                    </p>

                </div>
            `;

            return;
        }


        // ----------------------------------------------------
        // Build history
        // ----------------------------------------------------

        let historyHTML = "";


        scans.forEach(scan => {

            let riskClass = "low";


            if (scan.risk_level === "HIGH RISK") {

                riskClass = "high";

            } else if (scan.risk_level === "MEDIUM RISK") {

                riskClass = "medium";
            }


            const message =
                String(scan.message || "");


            const preview =
                message.length > 100
                    ? message.substring(0, 100) + "..."
                    : message;


            const score =
                Math.min(
                    Math.max(Number(scan.risk_score) || 0, 0),
                    100
                );


            historyHTML += `

                <div class="history-item ${riskClass}">

                    <div class="history-main">

                        <span class="history-risk">
                            ${escapeHTML(scan.risk_level)}
                        </span>

                        <p>
                            ${escapeHTML(preview)}
                        </p>

                    </div>


                    <div class="history-score">

                        <strong>
                            ${score}
                        </strong>

                        <small>
                            /100
                        </small>

                    </div>

                </div>
            `;
        });


        historyContainer.innerHTML =
            historyHTML;


    } catch (error) {

        historyContainer.innerHTML = `
            <div class="history-empty">
                <p>
                    Unable to load scan history.
                </p>
            </div>
        `;
    }
}


// ============================================================
// CHARACTER COUNT
// ============================================================

if (messageInput && characterCount) {

    messageInput.addEventListener(
        "input",
        function () {

            const length =
                this.value.length;


            characterCount.textContent =
                `${length} / ${MAX_MESSAGE_LENGTH} characters`;


            if (length > MAX_MESSAGE_LENGTH) {

                characterCount.style.color =
                    "#B23A2E";

            } else {

                characterCount.style.color =
                    "";
            }
        }
    );
}


// ============================================================
// KEYBOARD SHORTCUT
// ============================================================

if (messageInput) {

    messageInput.addEventListener(
        "keydown",
        function (event) {

            // Ctrl + Enter → Analyze
            if (
                event.ctrlKey &&
                event.key === "Enter"
            ) {

                event.preventDefault();

                analyzeMessage();
            }
        }
    );
}


// ============================================================
// LOAD HISTORY WHEN PAGE OPENS
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        loadHistory();
    }
);