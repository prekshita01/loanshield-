// LoanShield AI Client-Side Scripts

document.addEventListener("DOMContentLoaded", function () {
    // 1. Handle Scan Form Submission
    const scanForm = document.getElementById("scan-form");
    if (scanForm) {
        scanForm.addEventListener("submit", function (e) {
            e.preventDefault();
            const queryInput = document.getElementById("scan-query");
            const query = queryInput.value.trim();
            
            if (!query) return;

            // Show loading scanner panel
            const inputPanel = document.getElementById("input-panel");
            const loaderPanel = document.getElementById("loader-panel");
            
            inputPanel.classList.add("hidden");
            loaderPanel.classList.remove("hidden");

            // Progress steps orchestration
            const steps = [
                { id: "step-playstore", text: "Connecting to Google Play Store & fetching metadata..." },
                { id: "step-rbi", text: "Analyzing RBI Digital Lending Compliance guidelines..." },
                { id: "step-vt", text: "Querying VirusTotal Threat intelligence feeds..." },
                { id: "step-osint", text: "Analyzing DNS, SSL handshake and WHOIS registration..." },
                { id: "step-risk", text: "Computing fraud score weighting & generating classification..." }
            ];

            let currentStepIdx = 0;

            function runStepProgress() {
                if (currentStepIdx > 0) {
                    // Complete previous step
                    const prevStep = document.getElementById(steps[currentStepIdx - 1].id);
                    if (prevStep) {
                        prevStep.classList.remove("active", "text-blue-400");
                        prevStep.classList.add("completed", "text-emerald-500");
                        prevStep.querySelector(".icon").innerHTML = '<i class="fas fa-check-circle mr-2"></i>';
                    }
                }

                if (currentStepIdx < steps.length) {
                    // Activate current step
                    const currentStep = document.getElementById(steps[currentStepIdx].id);
                    if (currentStep) {
                        currentStep.classList.remove("pending", "text-gray-500");
                        currentStep.classList.add("active", "text-blue-400");
                        currentStep.querySelector(".icon").innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>';
                    }
                    currentStepIdx++;
                    
                    // Progressive delays to simulate real execution
                    setTimeout(runStepProgress, 1200);
                }
            }

            // Start step progress simulation visually while submitting request
            runStepProgress();

            // Submit scanning request to API
            fetch("/api/scan", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: new URLSearchParams({
                    query: query
                })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error("Scan request failed");
                }
                return response.json();
            })
            .then(data => {
                if (data.status === "success") {
                    // Small delay to let final step shine
                    setTimeout(() => {
                        window.location.href = `/scan/${data.scan_id}`;
                    }, 1000);
                } else {
                    alert("Error: " + (data.message || "Failed to scan target."));
                    resetSearchForm();
                }
            })
            .catch(error => {
                console.error("Scanning Error:", error);
                alert("Scanning encountered an error. Please try again.");
                resetSearchForm();
            });
        });
    }

    function resetSearchForm() {
        const inputPanel = document.getElementById("input-panel");
        const loaderPanel = document.getElementById("loader-panel");
        if (inputPanel && loaderPanel) {
            inputPanel.classList.remove("hidden");
            loaderPanel.classList.add("hidden");
        }
    }
});

// Helper to render Chart.js Gauge/Donut Chart for Risk Score
function renderRiskScoreChart(canvasId, score, verdict) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    let color = "#10b981"; // Safe (Green)
    if (verdict === "SUSPICIOUS") {
        color = "#f59e0b"; // Suspicious (Orange)
    } else if (verdict === "HIGH RISK") {
        color = "#ef4444"; // Danger (Red)
    }

    const data = {
        datasets: [{
            data: [score, 100 - score],
            backgroundColor: [color, "#1f2937"],
            borderWidth: 0,
            circumference: 180,
            rotation: 270,
            cutout: "80%"
        }]
    };

    const config = {
        type: "doughnut",
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            }
        }
    };

    new Chart(ctx, config);
}

// Helper to render Compliance Radar/Bar Chart
function renderComplianceChart(canvasId, scores) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    const data = {
        labels: ["Lender Disclosure", "Interest transparency", "Grievance redressal", "Privacy Policy", "Data Privacy", "Fair Recovery"],
        datasets: [{
            label: "Compliance Metrics",
            data: scores,
            backgroundColor: "rgba(59, 130, 246, 0.2)",
            borderColor: "#3b82f6",
            borderWidth: 2,
            pointBackgroundColor: "#3b82f6",
            pointBorderColor: "#fff",
            pointHoverBackgroundColor: "#fff",
            pointHoverBorderColor: "#3b82f6"
        }]
    };

    const config = {
        type: "radar",
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                r: {
                    angleLines: { color: "rgba(255, 255, 255, 0.1)" },
                    grid: { color: "rgba(255, 255, 255, 0.1)" },
                    pointLabels: { color: "#9ca3af" },
                    ticks: { display: false },
                    suggestedMin: 0,
                    suggestedMax: 100
                }
            }
        }
    };

    new Chart(ctx, config);
}
