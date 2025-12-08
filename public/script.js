const uploadForm = document.getElementById('uploadForm');
const analyzeBtn = document.getElementById('analyzeBtn');
const loadingDiv = document.getElementById('loading');
const resultsDiv = document.getElementById('results');
const errorDiv = document.getElementById('error');
const downloadBtn = document.getElementById('downloadBtn');

let currentResults = null;

uploadForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = new FormData();
    const owaspFile = document.getElementById('owaspReport').files[0];
    const dependenciesFile = document.getElementById('dependencies').files[0];
    
    if (!owaspFile || !dependenciesFile) {
        showError('Please select both files');
        return;
    }
    
    formData.append('owaspReport', owaspFile);
    formData.append('dependencies', dependenciesFile);
    
    // Show loading, hide results and error
    loadingDiv.classList.remove('hidden');
    resultsDiv.classList.add('hidden');
    errorDiv.classList.add('hidden');
    analyzeBtn.disabled = true;
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Analysis failed');
        }
        
        currentResults = data;
        displayResults(data);
        
    } catch (error) {
        showError(error.message || 'Failed to analyze files. Please check your files and try again.');
    } finally {
        loadingDiv.classList.add('hidden');
        analyzeBtn.disabled = false;
    }
});

function displayResults(data) {
    const { falsePositives, summary } = data;
    
    // Update summary
    const summaryText = document.getElementById('summaryText');
    summaryText.textContent = `Total OWASP Findings: ${summary.totalOWASPFindings} | ` +
                              `Direct False Positives: ${summary.directFalsePositives} | ` +
                              `Nested False Positives: ${summary.nestedFalsePositives}`;
    
    // Display direct dependencies false positives
    const directDepsDiv = document.getElementById('directDependencies');
    if (falsePositives.directDependencies.length === 0) {
        directDepsDiv.innerHTML = '<p class="no-results">No false positives found in direct dependencies.</p>';
    } else {
        directDepsDiv.innerHTML = falsePositives.directDependencies.map(item => `
            <div class="result-item">
                <h4>${escapeHtml(item.dependencyName)}</h4>
                <div class="version-info">
                    <strong>Reported Version:</strong> ${escapeHtml(item.reportedVersion)}
                    ${item.actualVersions ? `<br><strong>Actual Versions:</strong> ${escapeHtml(item.actualVersions.join(', '))}` : ''}
                </div>
                <div class="reason">${escapeHtml(item.reason)}</div>
            </div>
        `).join('');
    }
    
    // Display nested libraries false positives
    const nestedLibsDiv = document.getElementById('nestedLibraries');
    if (falsePositives.nestedLibraries.length === 0) {
        nestedLibsDiv.innerHTML = '<p class="no-results">No false positives found in nested libraries.</p>';
    } else {
        nestedLibsDiv.innerHTML = falsePositives.nestedLibraries.map(item => `
            <div class="result-item">
                <h4>${escapeHtml(item.libraryName)}</h4>
                <div class="version-info">
                    <strong>Reported Version:</strong> ${escapeHtml(item.reportedVersion)}
                    ${item.actualVersions ? `<br><strong>Actual Versions:</strong> ${escapeHtml(item.actualVersions.join(', '))}` : ''}
                </div>
                ${item.parentDependency ? `<div class="parent-info">Parent: ${escapeHtml(item.parentDependency)}</div>` : ''}
                <div class="reason">${escapeHtml(item.reason)}</div>
            </div>
        `).join('');
    }
    
    // Show results
    resultsDiv.classList.remove('hidden');
}

function showError(message) {
    errorDiv.classList.remove('hidden');
    document.getElementById('errorMessage').textContent = message;
    resultsDiv.classList.add('hidden');
}

downloadBtn.addEventListener('click', () => {
    if (!currentResults) {
        showError('No results to download');
        return;
    }
    
    const { falsePositives, summary } = currentResults;
    const timestamp = new Date().toLocaleString();
    
    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP False Positives Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        h1 { margin: 0 0 10px 0; }
        .timestamp { opacity: 0.9; font-size: 14px; }
        .summary {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary h2 { margin-top: 0; color: #667eea; }
        .stat { 
            display: inline-block;
            margin-right: 30px;
            font-size: 16px;
        }
        .stat strong { color: #667eea; }
        .section {
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #667eea;
            margin-top: 0;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .result-item {
            background: #f8f9fa;
            padding: 15px;
            margin: 15px 0;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }
        .result-item h4 {
            margin: 0 0 10px 0;
            color: #333;
            font-size: 18px;
        }
        .version-info, .parent-info {
            margin: 8px 0;
            font-size: 14px;
        }
        .reason {
            margin-top: 10px;
            padding: 10px;
            background: white;
            border-radius: 4px;
            font-size: 14px;
            line-height: 1.5;
        }
        .no-results {
            color: #28a745;
            font-style: italic;
            padding: 20px;
            text-align: center;
        }
        @media print {
            body { background: white; }
            .section { box-shadow: none; border: 1px solid #ddd; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP False Positives Report</h1>
        <div class="timestamp">Generated: ${escapeHtml(timestamp)}</div>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="stat"><strong>Total OWASP Findings:</strong> ${summary.totalOWASPFindings}</div>
        <div class="stat"><strong>Direct False Positives:</strong> ${summary.directFalsePositives}</div>
        <div class="stat"><strong>Nested False Positives:</strong> ${summary.nestedFalsePositives}</div>
    </div>
    
    <div class="section">
        <h2>Direct Dependencies False Positives</h2>
        ${falsePositives.directDependencies.length === 0 
            ? '<p class="no-results">No false positives found in direct dependencies.</p>'
            : falsePositives.directDependencies.map(item => `
                <div class="result-item">
                    <h4>${escapeHtml(item.dependencyName)}</h4>
                    <div class="version-info">
                        <strong>Reported Version:</strong> ${escapeHtml(item.reportedVersion)}
                        ${item.actualVersions ? `<br><strong>Actual Versions:</strong> ${escapeHtml(item.actualVersions.join(', '))}` : ''}
                    </div>
                    <div class="reason">${escapeHtml(item.reason)}</div>
                </div>
            `).join('')
        }
    </div>
    
    <div class="section">
        <h2>Nested Libraries False Positives</h2>
        ${falsePositives.nestedLibraries.length === 0
            ? '<p class="no-results">No false positives found in nested libraries.</p>'
            : falsePositives.nestedLibraries.map(item => `
                <div class="result-item">
                    <h4>${escapeHtml(item.libraryName)}</h4>
                    <div class="version-info">
                        <strong>Reported Version:</strong> ${escapeHtml(item.reportedVersion)}
                        ${item.actualVersions ? `<br><strong>Actual Versions:</strong> ${escapeHtml(item.actualVersions.join(', '))}` : ''}
                    </div>
                    ${item.parentDependency ? `<div class="parent-info"><strong>Parent:</strong> ${escapeHtml(item.parentDependency)}</div>` : ''}
                    <div class="reason">${escapeHtml(item.reason)}</div>
                </div>
            `).join('')
        }
    </div>
</body>
</html>
    `;
    
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `false_positives_report_${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
});

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

