// script.js - Consolidated version with all HTML script content

// DOM Elements
const phishingDetectorBtn = document.getElementById('phishingDetectorBtn');
const scamDetectorBtn = document.getElementById('scamDetectorBtn');
const phishingMode = document.getElementById('phishingMode');
const scamMode = document.getElementById('scamMode');
const urlInput = document.getElementById('urlInput');
const scamUrlInput = document.getElementById('scamUrlInput');
const scanBtn = document.getElementById('scanBtn');
const scamScanBtn = document.getElementById('scamScanBtn');
const loading = document.getElementById('loading');
const result = document.getElementById('result');
const analysisSections = document.getElementById('analysisSections');

// Global variables for loading tracking
let scanStartTime;
let loadingInterval;

// Toggle between phishing and scam detector modes
phishingDetectorBtn.addEventListener('click', function() {
    phishingMode.classList.add('active');
    scamMode.classList.remove('active');
    phishingDetectorBtn.classList.add('active');
    scamDetectorBtn.classList.remove('active');
    urlInput.focus();
});

scamDetectorBtn.addEventListener('click', function() {
    scamMode.classList.add('active');
    phishingMode.classList.remove('active');
    scamDetectorBtn.classList.add('active');
    phishingDetectorBtn.classList.remove('active');
    scamUrlInput.focus();
});

// Add event listeners for both scan buttons
scanBtn.addEventListener('click', function() {
    const url = urlInput.value.trim();
    if (url) {
        scanUrl(url, 'phishing');
    } else {
        alert('Please enter a URL to scan');
    }
});

scamScanBtn.addEventListener('click', function() {
    const url = scamUrlInput.value.trim();
    if (url) {
        scanUrl(url, 'scam');
    } else {
        alert('Please enter a URL to scan');
    }
});

// Enter key support for both inputs
urlInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        scanBtn.click();
    }
});

scamUrlInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        scamScanBtn.click();
    }
});

function scanUrl(url, mode = 'phishing') {
    console.log(`Scanning URL in ${mode} mode: ${url}`);
    
    const loading = document.getElementById('loading');
    const result = document.getElementById('result');
    const analysisSections = document.getElementById('analysisSections');
    
    // Initialize loading steps
    initializeLoadingSteps();
    
    // Show loading, hide previous results and analysis sections
    loading.classList.remove('hidden');
    result.classList.add('hidden');
    analysisSections.style.display = 'none';
    result.innerHTML = '';

    // Reset analysis sections to loading state
    resetAnalysisSections();

    // Start timer and progress tracking
    scanStartTime = Date.now();
    startLoadingTimer();
    updateProgressBar(10); // Start at 10%

    // ⭐ INCREASED TIMEOUT to 60 seconds
    const timeout = 120000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
        controller.abort();
        clearLoadingInterval();
    }, timeout);

    // Make API call to backend
    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url }),
        signal: controller.signal
    })
    .then(response => {
        clearTimeout(timeoutId);
        if (!response.ok) {
            return response.json().then(err => { 
                throw new Error(err.error || `Server error: ${response.status}`); 
            });
        }
        return response.json();
    })
    .then(data => {
        clearLoadingInterval();
        updateProgressBar(100);
        updateLoadingStep(5, true); // Mark final step as completed
        
        // Small delay to show completion
        setTimeout(() => {
            loading.classList.add('hidden');
            processScanResults(data, mode);
        }, 500);
        
    })
    .catch(error => {
        clearTimeout(timeoutId);
        clearLoadingInterval();
        loading.classList.add('hidden');
        
        if (error.name === 'AbortError') {
            showError('Scan took too long. Please try again.');
        } else {
            console.error('Scan error:', error);
            showError(error.message || 'Failed to scan URL. Please check your connection and try again.');
        }
    });
}

// New function to initialize loading steps
function initializeLoadingSteps() {
    const steps = [1, 2, 3, 4, 5];
    steps.forEach(step => {
        const stepElement = document.getElementById(`step${step}`);
        stepElement.className = 'step';
        const icon = stepElement.querySelector('.step-icon');
        icon.textContent = '⏳';
    });
    
    // Activate first step
    updateLoadingStep(1, false);
    updateProgressBar(0);
}

// New function to update loading steps
function updateLoadingStep(stepNumber, isCompleted = false) {
    const stepElement = document.getElementById(`step${stepNumber}`);
    const icon = stepElement.querySelector('.step-icon');
    
    if (isCompleted) {
        stepElement.className = 'step completed';
        icon.textContent = '✅';
    } else {
        stepElement.className = 'step active';
        icon.textContent = '🔍';
        
        // Update progress bar based on step
        const progress = (stepNumber / 5) * 80; // 80% max until completion
        updateProgressBar(progress);
    }
}

// New function to update progress bar
function updateProgressBar(percentage) {
    const progressFill = document.getElementById('progressFill');
    progressFill.style.width = `${Math.min(100, percentage)}%`;
}

// New function to start loading timer
function startLoadingTimer() {
    const timeElement = document.getElementById('loadingTime');
    
    loadingInterval = setInterval(() => {
        const elapsedSeconds = Math.floor((Date.now() - scanStartTime) / 1000);
        timeElement.textContent = `Elapsed time: ${elapsedSeconds}s`;
        
        // Simulate step progression (fallback if backend doesn't send updates)
        if (elapsedSeconds > 25) updateLoadingStep(4, false);
        else if (elapsedSeconds > 18) updateLoadingStep(3, false);
        else if (elapsedSeconds > 10) updateLoadingStep(2, false);
        
    }, 1000);
}

// New function to clear loading interval
function clearLoadingInterval() {
    if (loadingInterval) {
        clearInterval(loadingInterval);
        loadingInterval = null;
    }
}

// ✅ FIXED: Use the correct data structure from Flask backend
function processScanResults(data, mode) {
    console.log("🔍 FULL API RESPONSE:", data);
    console.log("📸 SCREENSHOT DATA IN RESPONSE:", data.screenshot);
    
    if (data.error) {
        showError(data.error);
        return;
    }

    // Display main result
    if (data.is_phishing !== undefined) {
        displayMainResult(data, mode);
    } else {
        showError('No analysis results available');
    }
    
    // Debug screenshot data
    if (data.screenshot) {
        console.log("✅ Screenshot data found:", {
            url: data.screenshot.url,
            filename: data.screenshot.filename,
            error: data.screenshot.error,
            success: data.screenshot.success
        });
        console.log("🔄 Calling updateScreenshot...");
        updateScreenshot(data.screenshot);
    } else {
        console.log("❌ NO SCREENSHOT DATA IN RESPONSE!");
        updateScreenshot(null);
    }
    
    // Update other analysis sections
    updateAnalysisSections(data);
    
    // Display image analysis results
    if (data.image_analysis) {
        displayImageAnalysis(data.image_analysis);
    }
    
    // Show analysis sections
    document.getElementById('analysisSections').style.display = 'block';
    
    // Smooth scroll to results
    document.getElementById('result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
function displayMainResult(data, mode) {
    const isPhishing = data.is_phishing;
    const probability = data.probability ? (data.probability * 100).toFixed(2) : "N/A";
    const confidence = data.confidence || 'Unknown';
    const modelUsed = data.model_used || 'Machine Learning Model';
    
    let resultHTML = `
        <div class="result-card ${isPhishing ? 'phishing' : 'legitimate'}">
            <h3>Scan Results for: ${data.url}</h3>
            <div class="status ${isPhishing ? 'phishing-status' : 'legitimate-status'}">
                ${isPhishing ? '🚨 PHISHING WEBSITE DETECTED' : '✅ LEGITIMATE WEBSITE'}
            </div>
            <div class="details">
                <p><strong>Confidence:</strong> ${confidence}</p>
                <p><strong>Scan Method:</strong> ${data.scan_method || 'Hybrid Analysis'}</p>
    `;

    // Add threat intelligence info
    if (data.in_threat_feed) {
        resultHTML += `
            <div class="threat-warning">
                <p>⚠️ <strong>Threat Intelligence:</strong> Found in ${(data.threat_sources || ['threat database']).join(', ')}</p>
            </div>
        `;
    }

    // Add trusted subdomain info
    if (data.trusted_subdomain) {
        resultHTML += `
            <div class="trusted-info">
                <p>✅ <strong>Trusted Platform:</strong> ${data.subdomain_provider || 'Trusted service'}</p>
            </div>
        `;
    }

    // Add special message if available
    if (data.special_message) {
        resultHTML += `
            <div class="special-message">
                <p>${data.special_message}</p>
            </div>
        `;
    }

    // Add Google Safe Browsing status if checked
    if (data.google_safe_browsing_checked !== undefined) {
        resultHTML += `
            <div class="google-status">
                <p>${data.google_safe_browsing_success ? '✅' : '⚠️'} <strong>Google Safe Browsing:</strong> 
                ${data.google_safe_browsing_success ? 'Checked' : 'Unavailable: ' + (data.google_safe_browsing_error || 'Unknown error')}</p>
            </div>
        `;
    }

    // Add mode-specific advice
    if (mode === 'scam') {
        resultHTML += `
            <div class="freelancer-advice">
                <h4>Freelancer Advice:</h4>
                ${isPhishing ? 
                    '<p>⚠️ This appears to be a scam website. Avoid sharing personal information or accepting jobs from this source.</p>' :
                    '<p>✅ This website appears legitimate. Still exercise caution and verify client identity through multiple channels.</p>'
                }
            </div>
        `;
    } else {
        resultHTML += `
            <div class="general-advice">
                <h4>Security Advice:</h4>
                ${isPhishing ? 
                    '<p>⚠️ Do not enter any personal information on this website. Verify the URL and contact the legitimate organization directly.</p>' :
                    '<p>✅ This website appears safe. Continue to practice good security habits like using strong passwords.</p>'
                }
            </div>
        `;
    }

    resultHTML += `
            </div>
        </div>
    `;

    result.innerHTML = resultHTML;
    result.classList.remove('hidden');
}

function resetAnalysisSections() {
    // Reset contact information
    document.getElementById('emailList').innerHTML = '<li class="no-contact">No email addresses found</li>';
    document.getElementById('phoneList').innerHTML = '<li class="no-contact">No phone numbers found</li>';
    document.getElementById('contactPageList').innerHTML = '<li class="no-contact">No contact pages found</li>';
    
    // Reset screenshot
    const screenshotContainer = document.getElementById('screenshotContainer');
    screenshotContainer.innerHTML = `
        <div class="screenshot-placeholder">
            <p>Screenshot will be displayed here after analysis</p>
        </div>
    `;
    
    // Reset image analysis
    const imageAnalysisResult = document.getElementById('imageAnalysisResult');
    imageAnalysisResult.style.display = 'none';
    document.getElementById('imageAnalysisContent').innerHTML = '';
    
    // Reset technical analysis
    document.getElementById('sslStatus').textContent = 'Checking...';
    document.getElementById('sslStatus').className = 'tech-value status-info';
    document.getElementById('sslExpiry').textContent = 'N/A';
    document.getElementById('dnsCount').textContent = 'Checking...';
    document.getElementById('domainAge').textContent = 'N/A';
    document.getElementById('safeBrowsing').textContent = 'Checking...';
    document.getElementById('safeBrowsing').className = 'tech-value status-info';
    document.getElementById('blacklistStatus').textContent = 'Clean';
    document.getElementById('blacklistStatus').className = 'tech-value status-safe';
    document.getElementById('reachabilityStatus').textContent = 'Checking...';
    document.getElementById('reachabilityStatus').className = 'tech-value status-info';
    document.getElementById('responseTime').textContent = 'N/A';
}

function updateAnalysisSections(data) {
    // Update contact information
    if (data.contacts_found) {
        updateContactInformation(data.contacts_found);
    }
    
    // Update technical analysis
    if (data.features || data.threat_intel) {
        updateTechnicalAnalysis(data.features, data.threat_intel);
    }
    
    // Update screenshot
    if (data.screenshot) {
        updateScreenshot(data.screenshot);
    }
}

function updateContactInformation(contacts) {
    const emailList = document.getElementById('emailList');
    const phoneList = document.getElementById('phoneList');
    const contactPageList = document.getElementById('contactPageList');
    
    // Update emails
    if (contacts.emails && contacts.emails.length > 0) {
        emailList.innerHTML = contacts.emails.map(email => `<li>${email}</li>`).join('');
    } else {
        emailList.innerHTML = '<li class="no-contact">No email addresses found</li>';
    }
    
    // Update phones
    if (contacts.phones && contacts.phones.length > 0) {
        phoneList.innerHTML = contacts.phones.map(phone => `<li>${phone}</li>`).join('');
    } else {
        phoneList.innerHTML = '<li class="no-contact">No phone numbers found</li>';
    }
    
    // Update contact pages
    if (contacts.contact_pages && contacts.contact_pages.length > 0) {
        contactPageList.innerHTML = contacts.contact_pages.map(page => `<li>${page}</li>`).join('');
    } else {
        contactPageList.innerHTML = '<li class="no-contact">No contact pages found</li>';
    }
}

function updateTechnicalAnalysis(features, threatIntel) {
    // Update SSL information
    if (features && features.has_ssl !== undefined) {
        const sslStatus = document.getElementById('sslStatus');
        sslStatus.textContent = features.has_ssl ? 'Valid' : 'Invalid';
        sslStatus.className = features.has_ssl ? 'tech-value status-safe' : 'tech-value status-danger';
    }
    
    if (features && features.ssl_expiry) {
        document.getElementById('sslExpiry').textContent = features.ssl_expiry;
    } else {
        document.getElementById('sslExpiry').textContent = 'N/A';
    }
    
    // Update DNS information
    if (features && features.dns_records !== undefined) {
        const dnsCount = document.getElementById('dnsCount');
        if (typeof features.dns_records === 'object') {
            let totalRecords = 0;
            if (features.dns_records.A) totalRecords += features.dns_records.A.length;
            if (features.dns_records.MX) totalRecords += features.dns_records.MX.length;
            if (features.dns_records.NS) totalRecords += features.dns_records.NS.length;
            if (features.dns_records.TXT) totalRecords += features.dns_records.TXT.length;
            
            dnsCount.textContent = `${totalRecords} Records Found`;
            dnsCount.title = `A: ${features.dns_records.A?.length || 0}, MX: ${features.dns_records.MX?.length || 0}, NS: ${features.dns_records.NS?.length || 0}, TXT: ${features.dns_records.TXT?.length || 0}`;
        } else {
            dnsCount.textContent = features.dns_records;
        }
    }
    
    if (features && features.domain_age) {
        document.getElementById('domainAge').textContent = features.domain_age;
    } else {
        document.getElementById('domainAge').textContent = 'N/A';
    }
    
    // ✅ FULLY FIXED: Threat intelligence with unreachable website handling
    if (threatIntel) {
        const safeBrowsing = document.getElementById('safeBrowsing');
        const blacklistStatus = document.getElementById('blacklistStatus');
        
        // Check if website is unreachable (using features.reachable)
        const isUnreachable = features && features.reachable === false;
        
        if (isUnreachable) {
            // Website is unreachable - show appropriate status
            safeBrowsing.textContent = 'Unreachable';
            safeBrowsing.className = 'tech-value status-warning';
            
            // Use heuristic detection or blacklist status for unreachable sites
            if (threatIntel.heuristic_detected || threatIntel.blacklisted) {
                blacklistStatus.textContent = 'Suspicious (Heuristic)';
                blacklistStatus.className = 'tech-value status-danger';
            } else {
                blacklistStatus.textContent = 'Unknown';
                blacklistStatus.className = 'tech-value status-warning';
            }
        } else {
            // Website is reachable - normal display logic
            safeBrowsing.textContent = threatIntel.safe_browsing ? 'Reported' : 'Clean';
            safeBrowsing.className = threatIntel.safe_browsing ? 'tech-value status-danger' : 'tech-value status-safe';
            
            blacklistStatus.textContent = threatIntel.blacklisted ? 'Blacklisted' : 'Clean';
            blacklistStatus.className = threatIntel.blacklisted ? 'tech-value status-danger' : 'tech-value status-safe';
        }
    } else {
        // Fallback if no threat intelligence data
        const safeBrowsing = document.getElementById('safeBrowsing');
        const blacklistStatus = document.getElementById('blacklistStatus');
        safeBrowsing.textContent = 'Unknown';
        safeBrowsing.className = 'tech-value status-warning';
        blacklistStatus.textContent = 'Unknown';
        blacklistStatus.className = 'tech-value status-warning';
    }
    
    // Update reachability
    if (features && features.reachable !== undefined) {
        const reachabilityStatus = document.getElementById('reachabilityStatus');
        reachabilityStatus.textContent = features.reachable ? 'Reachable' : 'Unreachable';
        reachabilityStatus.className = features.reachable ? 'tech-value status-safe' : 'tech-value status-danger';
    }
    
    if (features && features.response_time) {
        document.getElementById('responseTime').textContent = features.response_time;
    } else {
        document.getElementById('responseTime').textContent = 'N/A';
    }
}
function updateScreenshot(screenshotData) {
    const screenshotContainer = document.getElementById('screenshotContainer');
    
    console.log("🖼️ Screenshot data received:", screenshotData);
    
    // Clear container
    screenshotContainer.innerHTML = '';
    
    if (!screenshotData || screenshotData.error) {
        const errorMsg = screenshotData?.error || 'No screenshot data available';
        const note = screenshotData?.note || '';
        
        screenshotContainer.innerHTML = `
            <div class="screenshot-placeholder">
                <p>${errorMsg}</p>
                ${note ? `<p class="note">${note}</p>` : ''}
            </div>
        `;
        return;
    }
    
    const screenshotUrl = screenshotData.url || 
                         (screenshotData.filename ? `/static/screenshots/${screenshotData.filename}` : null);
    
    if (screenshotUrl) {
        console.log("📸 Loading screenshot from:", screenshotUrl);
        
        screenshotContainer.innerHTML = `
            <div class="screenshot-with-loader">
                <img src="${screenshotUrl}" alt="Website Screenshot" class="screenshot-image" 
                     id="currentScreenshotImg">
                <p class="screenshot-info" id="screenshotStatusText">Loading screenshot...</p>
            </div>
        `;
        
        const img = document.getElementById('currentScreenshotImg');
        const statusText = document.getElementById('screenshotStatusText');
        
        img.onload = function() {
            console.log("✅ Screenshot loaded successfully");
            this.classList.add('loaded');
            if (statusText) {
                statusText.textContent = 'Website screenshot captured successfully';
                statusText.style.color = '#38a169'; // Success green
            }
        };
        
        img.onerror = function() {
            console.error("❌ Screenshot failed to load");
            screenshotContainer.innerHTML = `
                <div class="screenshot-placeholder">
                    <p>Failed to load screenshot</p>
                    <p class="note">The screenshot could not be displayed</p>
                    <button class="retry-btn" onclick="retryScreenshot('${screenshotUrl}')">Retry</button>
                </div>
            `;
        };
        
        // Fallback timeout
        setTimeout(() => {
            if (img && !img.classList.contains('loaded') && statusText && statusText.textContent === 'Loading screenshot...') {
                console.log("⏰ Screenshot load timeout");
                screenshotContainer.innerHTML = `
                    <div class="screenshot-placeholder">
                        <p>Screenshot load timeout</p>
                        <p class="note">The screenshot is taking too long to load</p>
                        <button class="retry-btn" onclick="retryScreenshot('${screenshotUrl}')">Retry</button>
                    </div>
                `;
            }
        }, 10000);
        
    } else {
        screenshotContainer.innerHTML = `
            <div class="screenshot-placeholder">
                <p>No screenshot available</p>
            </div>
        `;
    }
}

// Retry function
function retryScreenshot(url) {
    console.log("🔄 Retrying screenshot:", url);
    const screenshotContainer = document.getElementById('screenshotContainer');
    
    screenshotContainer.innerHTML = `
        <div class="screenshot-with-loader">
            <img src="${url}?retry=${Date.now()}" alt="Website Screenshot" class="screenshot-image" 
                 id="currentScreenshotImg">
            <p class="screenshot-info" id="screenshotStatusText">Retrying...</p>
        </div>
    `;
    
    const img = document.getElementById('currentScreenshotImg');
    const statusText = document.getElementById('screenshotStatusText');
    
    img.onload = function() {
        console.log("✅ Retry successful");
        this.classList.add('loaded');
        if (statusText) {
            statusText.textContent = 'Website screenshot loaded successfully';
            statusText.style.color = '#38a169';
        }
    };
    
    img.onerror = function() {
        console.error("❌ Retry failed");
        screenshotContainer.innerHTML = `
            <div class="screenshot-placeholder">
                <p>Failed to load screenshot</p>
                <p class="note">Please try scanning again</p>
            </div>
        `;
    };
}
// Separate load handler
function handleScreenshotLoad() {
    console.log("✅ Screenshot loaded successfully");
    const img = document.getElementById('screenshotImg');
    const info = document.getElementById('screenshotInfo');
    
    if (img) {
        img.classList.add('loaded');
    }
    if (info) {
        info.textContent = 'Website screenshot captured successfully';
    }
}

// Separate error handler
function handleScreenshotError() {
    console.error("❌ Screenshot failed to load");
    const loader = document.getElementById('screenshotLoader');
    const img = document.getElementById('screenshotImg');
    
    if (loader && img) {
        loader.innerHTML = `
            <div class="screenshot-placeholder">
                <p>Failed to load screenshot</p>
                <p class="note">The screenshot could not be displayed</p>
            </div>
        `;
    }
}
// New function to test image accessibility
function testImageAccessibility(url) {
    console.log("🔍 Testing image accessibility for:", url);
    
    const testImg = new Image();
    testImg.onload = function() {
        console.log("✅ TEST: Image URL is accessible - dimensions:", this.naturalWidth, "x", this.naturalHeight);
        document.getElementById('screenshotInfo').textContent = 'Website screenshot loaded successfully';
    };
    testImg.onerror = function() {
        console.log("❌ TEST: Image URL is NOT accessible:", url);
        document.getElementById('screenshotInfo').textContent = 'Failed to load screenshot - URL not accessible';
    };
    testImg.src = url;
}

// Error handler function
function handleScreenshotError(imgElement, url) {
    console.error("💥 Screenshot load failed:", {
        url: url,
        imgSrc: imgElement.src,
        naturalWidth: imgElement.naturalWidth,
        naturalHeight: imgElement.naturalHeight,
        complete: imgElement.complete,
        currentSrc: imgElement.currentSrc
    });
    
    const container = imgElement.parentNode;
    container.innerHTML = `
        <div class="screenshot-placeholder">
            <p>❌ Failed to load screenshot</p>
            <p class="note">URL: ${url}</p>
            <p class="note">The screenshot file exists but cannot be displayed.</p>
            <button class="retry-btn" onclick="retryScreenshot('${url}')">Retry Load</button>
        </div>
    `;
}

// Retry function
function retryScreenshot(url) {
    console.log("🔄 Retrying screenshot load:", url);
    const img = document.createElement('img');
    img.src = url + '?retry=' + Date.now(); // Cache bust
    img.onload = function() {
        document.getElementById('screenshotContainer').innerHTML = `
            <div class="screenshot-with-loader">
                <img src="${this.src}" alt="Website Screenshot" class="screenshot-image loaded">
                <p class="screenshot-info">Website screenshot (retry successful)</p>
            </div>
        `;
    };
}
function displayImageAnalysis(imageAnalysis) {
    const imageAnalysisResult = document.getElementById('imageAnalysisResult');
    const imageAnalysisContent = document.getElementById('imageAnalysisContent');
    
    if (!imageAnalysis) {
        imageAnalysisResult.style.display = 'none';
        return;
    }
    
    let analysisHTML = '';
    let resultClass = '';
    
    if (imageAnalysis.is_phishing) {
        resultClass = 'analysis-phishing';
        analysisHTML = `
            <div class="analysis-result ${resultClass}">
                <strong>Phishing Indicators Found:</strong>
                <ul>
                    ${imageAnalysis.reasons ? imageAnalysis.reasons.map(reason => `<li>${reason}</li>`).join('') : '<li>Suspicious visual elements detected</li>'}
                </ul>
                ${imageAnalysis.confidence ? `<p>Confidence: ${(imageAnalysis.confidence * 100).toFixed(2)}%</p>` : ''}
            </div>
        `;
    } else {
        resultClass = 'analysis-legitimate';
        analysisHTML = `
            <div class="analysis-result ${resultClass}">
                <strong>No significant phishing indicators found in images.</strong>
                ${imageAnalysis.confidence ? `<p>Confidence: ${(imageAnalysis.confidence * 100).toFixed(2)}%</p>` : ''}
            </div>
        `;
    }
    
    imageAnalysisContent.innerHTML = analysisHTML;
    imageAnalysisResult.style.display = 'block';
}

function showError(message) {
    const result = document.getElementById('result');
    result.innerHTML = `
        <div class="error">
            <h3>Error</h3>
            <p>${message}</p>
        </div>
    `;
    result.classList.remove('hidden');
    
    // Smooth scroll to error
    result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Initialize the page
document.addEventListener('DOMContentLoaded', function() {
    console.log('Phishing & Scam Detector initialized successfully');
});