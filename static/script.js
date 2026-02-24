document.getElementById('analyzeBtn').addEventListener('click', function() {
    const header = document.getElementById('headerInput').value;
    const resultsDiv = document.getElementById('results');
    const analyzeBtn = document.getElementById('analyzeBtn');

    if (!header.trim()) {
        resultsDiv.innerHTML = '<div class="card error-card"><p>Please paste an email header to analyze.</p></div>';
        return;
    }

    const originalBtnText = analyzeBtn.innerHTML;
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<span class="spinner"></span> Analyzing...';
    resultsDiv.innerHTML = '<p class="analyzing">Analyzing...</p>';

    fetch('/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ header: header })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Network response was not ok: ${response.statusText}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            resultsDiv.innerHTML = `<div class="card error-card"><p>${data.error}</p></div>`;
            return;
        }

        resultsDiv.innerHTML = ''; // Clear "Analyzing..." message

        const riskClass = data.risk_assessment.toLowerCase();
        
        // Helper to format status with icons
        const formatStatus = (status) => {
            const s = status.toLowerCase();
            const cls = (s === 'pass') ? 'status-pass' : (s === 'fail' ? 'status-fail' : 'status-neutral');
            const icon = (s === 'pass') ? '✅ ' : (s === 'fail' ? '❌ ' : '⚪ ');
            return `<span class="${cls}">${icon}${status}</span>`;
        };

        // --- Create Summary Card ---
        const summaryCard = `
            <div class="card summary-card risk-${riskClass}">
                <h2>Risk Assessment</h2>
                <div class="risk-badge">${data.risk_assessment}</div>
                ${data.suspicious_indicators.length > 0 
                    ? `<p>Found <strong>${data.suspicious_indicators.length}</strong> suspicious indicator(s).</p>` 
                    : '<p>No major suspicious indicators found.</p>'}
            </div>
        `;

        // --- Create Details Grid ---
        let detailsGrid = '<div class="details-grid">';

        // General Information Card
        if (data.metadata) {
            // Use textContent to prevent potential XSS from a malicious subject line
            const subjectEl = document.createElement('span');
            subjectEl.textContent = data.metadata.subject;
            detailsGrid += `
                <div class="card">
                    <h3>General Information</h3>
                    <div class="info-row"><span class="info-label">Subject</span> <span class="info-value">${subjectEl.innerHTML}</span></div>
                    <div class="info-row"><span class="info-label">Date</span> <span class="info-value">${data.metadata.date}</span></div>
                </div>
            `;
        }

        // Suspicious Indicators Card
        if (data.suspicious_indicators.length > 0) {
            detailsGrid += `
                <div class="card">
                    <h3>Suspicious Indicators</h3>
                    <ul class="suspicious-list">
                        ${data.suspicious_indicators.map(indicator => `<li>${indicator}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        // IP Analysis Card
        detailsGrid += `
            <div class="card">
                <h3>IP Address Analysis</h3>
                <div class="info-row"><span class="info-label">Origin IP</span> <span class="info-value">${data.ips.origin_ip || 'Not Found'}</span></div>`;

        // Add reputation details if they exist and there wasn't an error
        if (data.ip_reputation && !data.ip_reputation.error) {
            detailsGrid += `
                <div class="info-row"><span class="info-label">Country</span> <span class="info-value">${data.ip_reputation.country}</span></div>
                <div class="info-row"><span class="info-label">ISP</span> <span class="info-value">${data.ip_reputation.isp}</span></div>
                <div class="info-row"><span class="info-label">Organization</span> <span class="info-value">${data.ip_reputation.org}</span></div>
            `;
        } else if (data.ip_reputation && data.ip_reputation.error) {
            detailsGrid += `<div class="info-row"><span class="info-label">Reputation</span> <span class="info-value status-neutral">${data.ip_reputation.error}</span></div>`;
        }

        detailsGrid += `
                <div class="info-row"><span class="info-label">Public IPs</span> <span class="info-value">${data.ips.public.join(', ') || 'None'}</span></div>
                <div class="info-row"><span class="info-label">Private IPs</span> <span class="info-value">${data.ips.private.join(', ') || 'None'}</span></div>
            </div>
        `;

        // Authentication Card
        detailsGrid += `
            <div class="card">
                <h3>Authentication Results</h3>
                <div class="info-row"><span class="info-label">SPF</span> <span class="info-value">${formatStatus(data.authentication.spf)}</span></div>
                <div class="info-row"><span class="info-label">DKIM</span> <span class="info-value">${formatStatus(data.authentication.dkim)}</span></div>
                <div class="info-row"><span class="info-label">DMARC</span> <span class="info-value">${formatStatus(data.authentication.dmarc)}</span></div>
            </div>
        `;

        // Spoofing Card
        detailsGrid += `
            <div class="card">
                <h3>Spoofing Detection</h3>
                <div class="info-row"><span class="info-label">From</span> <span class="info-value">${data.spoofing.from}</span></div>
                <div class="info-row"><span class="info-label">Reply-To</span> <span class="info-value">${data.spoofing.reply_to}</span></div>
                <div class="info-row"><span class="info-label">Mismatch</span> <span class="info-value">${data.spoofing.mismatched ? '<span class="status-fail">Yes ⚠️</span>' : '<span class="status-pass">No ✅</span>'}</span></div>
            </div>
        `;

        detailsGrid += '</div>'; // Close details-grid

        resultsDiv.innerHTML = summaryCard + detailsGrid;

        // --- Create and append Export Button ---
        const exportContainer = document.createElement('div');
        exportContainer.style.textAlign = 'center';
        exportContainer.style.marginTop = '20px';
        exportContainer.innerHTML = `<button id="exportBtn">Export Results as PDF</button>`;
        
        resultsDiv.appendChild(exportContainer);

        document.getElementById('exportBtn').addEventListener('click', () => {
            generatePdf(data);
        });
    })
    .catch(error => {
        resultsDiv.innerHTML = '<div class="card error-card"><p>An error occurred during analysis. Please check the console for details.</p></div>';
        console.error('Error:', error);
    })
    .finally(() => {
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = originalBtnText;
    });
});

/**
 * Generates a PDF report from the analysis data.
 * @param {object} data The analysis data from the server.
 */
function generatePdf(data) {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: 'p', unit: 'mm', format: 'a4' });

    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 15;
    let yPos = 20;

    const checkPageBreak = () => {
        if (yPos > 270) { // A4 height is 297mm, leave some margin
            doc.addPage();
            yPos = 20;
        }
    };

    // --- Title ---
    doc.setFontSize(20);
    doc.setFont('helvetica', 'bold');
    doc.text('Email Header Analysis Report', pageWidth / 2, yPos, { align: 'center' });
    yPos += 15;

    // --- Risk Assessment ---
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('Risk Assessment', margin, yPos);
    yPos += 8;

    doc.setFontSize(12);
    let riskColor;
    switch (data.risk_assessment.toLowerCase()) {
        case 'high': riskColor = '#e74c3c'; break;
        case 'medium': riskColor = '#f1c40f'; break;
        default: riskColor = '#2ecc71'; break;
    }
    doc.setTextColor(riskColor);
    doc.setFont('helvetica', 'bold');
    doc.text(`Overall Risk: ${data.risk_assessment}`, margin, yPos);
    doc.setTextColor(0, 0, 0); // Reset color
    yPos += 10;

    // --- Helper for drawing sections ---
    const drawSection = (title, items) => {
        checkPageBreak();
        doc.setLineWidth(0.2);
        doc.line(margin, yPos, pageWidth - margin, yPos); // Separator line
        yPos += 8;

        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.text(title, margin, yPos);
        yPos += 7;

        doc.setFontSize(10);
        items.forEach(({ label, value, color }) => {
            checkPageBreak();
            doc.setFont('helvetica', 'bold');
            doc.text(label, margin, yPos);
            
            doc.setFont('helvetica', 'normal');
            if (color) doc.setTextColor(color);
            
            const valueX = margin + 35;
            const splitValue = doc.splitTextToSize(String(value), pageWidth - valueX - margin);
            doc.text(splitValue, valueX, yPos);
            
            if (color) doc.setTextColor(0, 0, 0); // Reset
            yPos += (splitValue.length * 4) + 2;
        });
        yPos += 3;
    };

    // --- Sections Data ---
    if (data.metadata) {
        drawSection('General Information', [
            { label: 'Subject:', value: data.metadata.subject },
            { label: 'Date:', value: data.metadata.date }
        ]);
    }

    if (data.suspicious_indicators.length > 0) {
        const indicators = data.suspicious_indicators.map(ind => ({ label: '•', value: ind, color: '#e74c3c' }));
        drawSection('Suspicious Indicators', indicators);
    }

    const getStatusColor = (status) => status.toLowerCase() === 'pass' ? '#2ecc71' : (status.toLowerCase() === 'fail' ? '#e74c3c' : '#7f8c8d');
    drawSection('Authentication Results', [
        { label: 'SPF:', value: data.authentication.spf, color: getStatusColor(data.authentication.spf) },
        { label: 'DKIM:', value: data.authentication.dkim, color: getStatusColor(data.authentication.dkim) },
        { label: 'DMARC:', value: data.authentication.dmarc, color: getStatusColor(data.authentication.dmarc) }
    ]);

    drawSection('Spoofing Detection', [
        { label: 'From:', value: data.spoofing.from },
        { label: 'Reply-To:', value: data.spoofing.reply_to },
        { label: 'Mismatch:', value: data.spoofing.mismatched ? 'Yes' : 'No', color: data.spoofing.mismatched ? '#e74c3c' : '#2ecc71' }
    ]);

    const ipItems = [
        { label: 'Origin IP:', value: data.ips.origin_ip || 'Not Found' },
    ];

    if (data.ip_reputation && !data.ip_reputation.error) {
        ipItems.push(
            { label: 'Country:', value: data.ip_reputation.country },
            { label: 'ISP:', value: data.ip_reputation.isp },
            { label: 'Organization:', value: data.ip_reputation.org }
        );
    }

    ipItems.push(
        { label: 'Public IPs:', value: data.ips.public.join(', ') || 'None' },
        { label: 'Private IPs:', value: data.ips.private.join(', ') || 'None' }
    );
    drawSection('IP Address Analysis', ipItems);

    doc.save('email-analysis-report.pdf');
}
