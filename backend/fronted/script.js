// =====================================================
// DIGITAL ARREST SHIELD
// =====================================================

const BACKEND_URL = "http://127.0.0.1:8000";

console.log("Digital Arrest Shield loaded");


// =====================================================
// HELPER
// =====================================================

function escapeHTML(value) {

    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}


function showBox(box, html) {

    if (!box) return;

    box.style.display = "block";

    box.innerHTML = html;

}


function riskIcon(level) {

    if (level === "HIGH") {
        return "🚨";
    }

    if (level === "MEDIUM") {
        return "⚠️";
    }

    return "🛡️";

}


// =====================================================
// BACKEND REQUEST
// =====================================================

async function sendToBackend(payload) {

    const response = await fetch(
        `${BACKEND_URL}/detect-scam`,
        {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify(payload)
        }
    );


    let data;

    try {

        data = await response.json();

    } catch {

        throw new Error(
            "Backend returned an invalid response."
        );

    }


    if (!response.ok) {

        throw new Error(
            data.detail ||
            "Backend request failed."
        );

    }


    return data;

}


// =====================================================
// DISPLAY RISK RESULT
// =====================================================

function renderRiskResult(box, data) {

    const flags =
        data.red_flags || [];

    const actions =
        data.safety_actions || [];


    const flagsHTML =
        flags.length

        ?

        `
        <ul>

            ${flags.map(function(flag) {

                return `
                    <li>
                        🚩 ${escapeHTML(flag)}
                    </li>
                `;

            }).join("")}

        </ul>
        `

        :

        `
        <p>
            No specific red flags detected.
        </p>
        `;


    const actionsHTML =
        actions.length

        ?

        `
        <ul>

            ${actions.map(function(action) {

                return `
                    <li>
                        🛡️ ${escapeHTML(action)}
                    </li>
                `;

            }).join("")}

        </ul>
        `

        :

        `
        <p>
            Verify the interaction independently.
        </p>
        `;


    showBox(
        box,

        `

        <h3>

            ${riskIcon(data.risk_level)}

            ${escapeHTML(data.risk_level)}
            RISK

        </h3>


        <div class="score">

            ${escapeHTML(data.risk_score)}/100

        </div>


        <p>

            Scam detected:

            <strong>

                ${
                    data.scam_detected
                        ? "YES"
                        : "NO"
                }

            </strong>

        </p>


        ${
            data.report_id !== undefined

            ?

            `
            <p>

                Report ID:

                <strong>
                    ${escapeHTML(data.report_id)}
                </strong>

            </p>
            `

            :

            ""
        }


        <hr>


        <h4>
            🚩 Red Flags
        </h4>

        ${flagsHTML}


        <hr>


        <h4>
            🛡️ Safety Actions
        </h4>

        ${actionsHTML}

        `
    );

}


// =====================================================
// SCAM CHECKER
// =====================================================

const optionButtons =
    document.querySelectorAll(
        ".question .options button"
    );


optionButtons.forEach(function(button) {

    button.addEventListener(
        "click",
        function() {

            const question =
                button.closest(".question");


            question
                .querySelectorAll("button")
                .forEach(function(btn) {

                    btn.classList.remove(
                        "selected"
                    );

                });


            button.classList.add(
                "selected"
            );

        }
    );

});


const analyzeButton =
    document.querySelector("#analyzeBtn");

const resultBox =
    document.querySelector("#result");


if (analyzeButton) {

    analyzeButton.type = "button";


    analyzeButton.addEventListener(
        "click",
        async function() {

            const questions =
                document.querySelectorAll(
                    ".question"
                );


            const payload = {};

            let missing = false;


            questions.forEach(
                function(question) {

                    const key =
                        question.dataset.key;


                    const selected =
                        question.querySelector(
                            ".selected"
                        );


                    if (!selected) {

                        missing = true;

                        return;

                    }


                    const value =
                        selected.dataset.value;


                    if (
                        key === "caller_claim"
                    ) {

                        payload[key] =
                            value;

                    } else {

                        payload[key] =
                            value === "true";

                    }

                }
            );


            if (missing) {

                showBox(
                    resultBox,

                    `
                    <h3>
                        ⚠️ Please answer all questions
                    </h3>

                    <p>
                        Complete all 8 questions
                        before analyzing.
                    </p>
                    `
                );

                return;

            }


            showBox(
                resultBox,

                `
                <h3>
                    ⏳ Analyzing Interaction...
                </h3>

                <p>
                    Connecting to FastAPI...
                </p>
                `
            );


            try {

                const data =
                    await sendToBackend(
                        payload
                    );


                renderRiskResult(
                    resultBox,
                    data
                );


                resultBox.scrollIntoView({
                    behavior: "smooth",
                    block: "center"
                });


            }

            catch (error) {

                showBox(
                    resultBox,

                    `
                    <h3>
                        ❌ Backend Connection Failed
                    </h3>

                    <p>
                        Make sure FastAPI is running at:
                    </p>

                    <strong>
                        ${BACKEND_URL}
                    </strong>

                    <p>
                        <strong>Error:</strong>
                        ${escapeHTML(error.message)}
                    </p>
                    `
                );

            }

        }
    );

}


// =====================================================
// MESSAGE ANALYZER
// =====================================================

const messageInput =
    document.querySelector(
        "#messageInput"
    );


const analyzeMessageButton =
    document.querySelector(
        "#analyzeMessageBtn"
    );


const messageResult =
    document.querySelector(
        "#messageResult"
    );


function detectMessageIndicators(
    message
) {

    const text =
        message.toLowerCase();


    const authority =
        /cbi|police|cyber crime|rbi|court|customs|government officer|official/
        .test(text);


    const arrest =
        /arrest|arrested|jail|warrant|criminal case|fir/
        .test(text);


    const money =
        /money|payment|pay now|transfer|fine|penalty|upi/
        .test(text);


    const otp =
        /otp|cvv|password|bank details|account number|upi pin/
        .test(text);


    const video =
        /video call|video-call|stay on call|camera on/
        .test(text);


    const app =
        /install app|download app|apk|application/
        .test(text);


    const urgency =
        /urgent|immediately|right now|do not disconnect|within.*minute/
        .test(text);


    let callerClaim =
        "Suspicious Message";


    if (text.includes("cbi")) {

        callerClaim =
            "CBI Officer";

    }

    else if (
        text.includes("police")
    ) {

        callerClaim =
            "Police Officer";

    }

    else if (
        text.includes("rbi")
    ) {

        callerClaim =
            "RBI Official";

    }

    else if (
        text.includes("court")
    ) {

        callerClaim =
            "Court Official";

    }


    return {

        caller_claim:
            callerClaim,

        claimed_authority:
            authority,

        threatened_arrest:
            arrest,

        demanded_money:
            money,

        asked_otp_bank:
            otp,

        forced_video_call:
            video,

        asked_install_app:
            app,

        created_urgency:
            urgency

    };

}


if (analyzeMessageButton) {

    analyzeMessageButton.addEventListener(
        "click",
        async function() {

            const message =
                messageInput.value.trim();


            if (!message) {

                showBox(
                    messageResult,

                    `
                    <h3>
                        ⚠️ No message entered
                    </h3>

                    <p>
                        Paste a suspicious
                        WhatsApp/SMS message first.
                    </p>
                    `
                );

                return;

            }


            showBox(
                messageResult,

                `
                <h3>
                    ⏳ Analyzing Message...
                </h3>

                <p>
                    Checking suspicious indicators...
                </p>
                `
            );


            try {

                const payload =
                    detectMessageIndicators(
                        message
                    );


                const data =
                    await sendToBackend(
                        payload
                    );


                renderRiskResult(
                    messageResult,
                    data
                );

            }

            catch (error) {

                showBox(
                    messageResult,

                    `
                    <h3>
                        ❌ Message Analysis Failed
                    </h3>

                    <p>
                        ${escapeHTML(
                            error.message
                        )}
                    </p>
                    `
                );

            }

        }
    );

}


// =====================================================
// SCREENSHOT ANALYZER
// =====================================================

const screenshotInput =
    document.querySelector(
        "#screenshotInput"
    );


const screenshotPreview =
    document.querySelector(
        "#screenshotPreview"
    );


const analyzeScreenshotButton =
    document.querySelector(
        "#analyzeScreenshotBtn"
    );


const screenshotResult =
    document.querySelector(
        "#screenshotResult"
    );


let selectedScreenshot = null;


if (screenshotInput) {

    screenshotInput.addEventListener(
        "change",
        function(event) {

            const file =
                event.target.files[0];


            if (!file) {
                return;
            }


            selectedScreenshot =
                file;


            const reader =
                new FileReader();


            reader.onload =
                function(e) {

                    screenshotPreview.innerHTML = `

                        <img
                            src="${e.target.result}"
                            alt="Suspicious screenshot">

                    `;

                };


            reader.readAsDataURL(file);

        }
    );

}


if (analyzeScreenshotButton) {

    analyzeScreenshotButton.addEventListener(
        "click",
        async function() {

            if (!selectedScreenshot) {

                showBox(
                    screenshotResult,

                    `
                    <h3>
                        ⚠️ Upload a screenshot first
                    </h3>

                    <p>
                        Select a WhatsApp, SMS
                        or chat screenshot.
                    </p>
                    `
                );

                return;

            }


            if (
                typeof Tesseract ===
                "undefined"
            ) {

                showBox(
                    screenshotResult,

                    `
                    <h3>
                        ❌ OCR unavailable
                    </h3>

                    <p>
                        Refresh the page and
                        try again.
                    </p>
                    `
                );

                return;

            }


            showBox(
                screenshotResult,

                `
                <h3>
                    📸 Reading Screenshot...
                </h3>

                <p>
                    OCR is extracting
                    visible text.
                </p>
                `
            );


            try {

                const result =
                    await Tesseract.recognize(
                        selectedScreenshot,
                        "eng",
                        {
                            logger: function(info) {

                                if (
                                    info.status ===
                                    "recognizing text"
                                ) {

                                    const percent =
                                        Math.round(
                                            (
                                                info.progress ||
                                                0
                                            ) * 100
                                        );


                                    showBox(
                                        screenshotResult,

                                        `
                                        <h3>
                                            📸 Reading Screenshot...
                                        </h3>

                                        <p>
                                            OCR Progress:
                                            ${percent}%
                                        </p>
                                        `
                                    );

                                }

                            }
                        }
                    );


                const extractedText =
                    result.data.text.trim();


                if (!extractedText) {

                    showBox(
                        screenshotResult,

                        `
                        <h3>
                            ⚠️ No readable text found
                        </h3>

                        <p>
                            Try a clearer screenshot.
                        </p>
                        `
                    );

                    return;

                }


                const payload =
                    detectMessageIndicators(
                        extractedText
                    );


                showBox(
                    screenshotResult,

                    `
                    <h3>
                        🔎 Text Extracted
                    </h3>

                    <div class="ocr-text">

                        ${escapeHTML(
                            extractedText
                        )}

                    </div>

                    <p>
                        Sending indicators
                        to backend...
                    </p>
                    `
                );


                const data =
                    await sendToBackend(
                        payload
                    );


                renderRiskResult(
                    screenshotResult,
                    data
                );

            }

            catch (error) {

                showBox(
                    screenshotResult,

                    `
                    <h3>
                        ❌ Screenshot Analysis Failed
                    </h3>

                    <p>
                        ${escapeHTML(
                            error.message
                        )}
                    </p>
                    `
                );

            }

        }
    );

}


// =====================================================
// VIDEO CALL SIMULATOR
// =====================================================

const simConversation =
    document.querySelector(
        "#sim-conversation"
    );


const simOptions =
    document.querySelector(
        "#sim-options"
    );


const simResult =
    document.querySelector(
        "#sim-result"
    );


const restartSimulator =
    document.querySelector(
        "#restart-simulator"
    );


function addSimulatorMessage(
    text,
    sender
) {

    const div =
        document.createElement(
            "div"
        );


    div.className =
        sender === "caller"
            ? "sim-message caller-message"
            : "sim-message user-message";


    div.innerHTML = `

        <span class="sim-speaker">

            ${
                sender === "caller"
                    ? "Caller"
                    : "You"
            }

        </span>

        <p>
            ${escapeHTML(text)}
        </p>

    `;


    simConversation.appendChild(
        div
    );


    simConversation.scrollTop =
        simConversation.scrollHeight;

}


function disableSimulatorOptions() {

    simOptions
        .querySelectorAll("button")
        .forEach(function(button) {

            button.disabled =
                true;

            button.style.opacity =
                "0.5";

        });

}


function showSimulatorResult(
    title,
    text
) {

    showBox(
        simResult,

        `
        <h3>
            ${title}
        </h3>

        <p>
            ${text}
        </p>
        `
    );


    disableSimulatorOptions();

}


function setSimulatorOptions(
    options
) {

    simOptions.innerHTML = "";


    options.forEach(
        function(option) {

            const button =
                document.createElement(
                    "button"
                );


            button.type =
                "button";


            button.className =
                "sim-choice";


            button.textContent =
                option.text;


            button.addEventListener(
                "click",
                function() {

                    handleSimulatorChoice(
                        option.action
                    );

                }
            );


            simOptions.appendChild(
                button
            );

        }
    );

}


function handleSimulatorChoice(
    choice
) {


    if (choice === "continue") {

        addSimulatorMessage(
            "I will continue the call.",
            "user"
        );


        addSimulatorMessage(
            "Do not disconnect. Your identity has been linked to a criminal case. You must cooperate immediately.",
            "caller"
        );


        setSimulatorOptions([

            {
                text:
                    "Continue",

                action:
                    "continue2"
            },

            {
                text:
                    "Ask for official verification",

                action:
                    "verify"
            },

            {
                text:
                    "End the call",

                action:
                    "end"
            }

        ]);


        return;

    }


    if (choice === "continue2") {

        addSimulatorMessage(
            "I will continue listening.",
            "user"
        );


        addSimulatorMessage(
            "Stay on this video call and provide your bank details and OTP for verification.",
            "caller"
        );


        setSimulatorOptions([

            {
                text:
                    "Share information",

                action:
                    "share"
            },

            {
                text:
                    "Verify independently",

                action:
                    "verify"
            },

            {
                text:
                    "End the call",

                action:
                    "end"
            }

        ]);


        return;

    }


    if (choice === "verify") {

        addSimulatorMessage(
            "I will verify the caller independently.",
            "user"
        );


        showSimulatorResult(
            "🛡️ Safer Response",

            "Do not rely on contact information supplied by the caller. Verify the claim using an independently found official channel."
        );


        return;

    }


    if (choice === "end") {

        addSimulatorMessage(
            "I am ending the suspicious call.",
            "user"
        );


        showSimulatorResult(
            "✅ Safer Response",

            "Ending the suspicious interaction prevents continued pressure. Verify the claim independently before taking action."
        );


        return;

    }


    if (choice === "share") {

        addSimulatorMessage(
            "I will share the requested information.",
            "user"
        );


        showSimulatorResult(
            "🚨 High-Risk Situation",

            "Never share OTPs, passwords or banking credentials because a caller demands them."
        );

    }

}


// Initial simulator buttons

if (simOptions) {

    simOptions
        .querySelectorAll("button")
        .forEach(function(button) {

            button.addEventListener(
                "click",
                function() {

                    handleSimulatorChoice(
                        button.dataset.choice
                    );

                }
            );

        });

}


// Restart simulator

if (restartSimulator) {

    restartSimulator.addEventListener(
        "click",
        function() {

            simConversation.innerHTML = `

                <div class="sim-message caller-message">

                    <span class="sim-speaker">
                        Caller
                    </span>

                    <p>
                        I am calling from the Cyber Crime
                        Department. Your identity has been
                        linked to a serious case.
                    </p>

                </div>

            `;


            simResult.style.display =
                "none";


            simResult.innerHTML =
                "";


            setSimulatorOptions([

                {
                    text:
                        "Continue the call",

                    action:
                        "continue"
                },

                {
                    text:
                        "Ask for official verification",

                    action:
                        "verify"
                },

                {
                    text:
                        "End the call",

                    action:
                        "end"
                }

            ]);

        }
    );

}

      