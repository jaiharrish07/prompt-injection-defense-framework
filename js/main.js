document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('analysis-form');
    const promptInput = document.getElementById('prompt-input');
    const compareSection = document.getElementById('compare-section');
    const directResponseContent = document.getElementById('direct-response-content');
    const frameworkResponseContent = document.getElementById('framework-response-content');
    const frameworkAnalysisDetails = document.getElementById('framework-analysis-details');

    // Handle form submission (Hybrid Compare)
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const prompt = promptInput.value.trim();
        if (!prompt) {
            alert('Please enter a prompt to analyze.');
            return;
        }
        
        // Show loading state
        compareSection.style.display = 'block';
        directResponseContent.innerHTML = '<div class="loading">Fetching direct response...</div>';
        frameworkResponseContent.innerHTML = '<div class="loading">Applying Hybrid Framework...</div>';
        frameworkAnalysisDetails.innerHTML = '';
        
        try {
            const response = await fetch('/compare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ prompt: prompt })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                displayCompareResults(data);
            } else {
                throw new Error(data.error || 'An error occurred during analysis');
            }
        } catch (error) {
            frameworkResponseContent.innerHTML = `<div class="error"><strong>Error:</strong> ${error.message}</div>`;
        }
    });
    
    function displayCompareResults(data) {
        directResponseContent.textContent = data.direct_response;
        frameworkResponseContent.textContent = data.framework_response;
        
        const analysis = data.analysis;
        
        // Build enhanced analysis display
        let html = `
            <div class="result-item">
                <span class="result-label">Action:</span>
                <span class="result-value action-${analysis.action.toLowerCase()}">${analysis.action}</span>
                <span class="mitigation-badge mitigation-${analysis.mitigation_mode.toLowerCase().replace('-', '')}">${analysis.mitigation_mode}</span>
            </div>
            <div class="result-item">
                <span class="result-label">Mitigation Strategy:</span>
                <p style="margin-top:5px; color:#555; font-style:italic;">${analysis.mitigation_description}</p>
            </div>
            <div class="result-item">
                <span class="result-label">Hybrid Risk:</span>
                <span class="result-value risk-score ${getClassForRiskLevel(analysis.risk_level)}">${analysis.risk_score}/100</span>
            </div>
        `;
        
        // Attack Taxonomy
        if (analysis.attack_taxonomy && analysis.attack_taxonomy.length > 0) {
            html += `<div class="result-item"><p><strong>🛡 Threat Classification:</strong></p>`;
            analysis.attack_taxonomy.forEach(attack => {
                html += `
                    <div class="threat-classification">
                        <strong>Attack Category:</strong> ${attack.name}<br>
                        <strong>Code:</strong> ${attack.code}<br>
                        <strong>Severity:</strong> <span style="color:#e74c3c;">${attack.severity}</span><br>
                        <strong>Industry Mapping:</strong> ${attack.owasp}
                    </div>
                `;
            });
            html += `</div>`;
        }
        
        // Decision Timeline
        if (analysis.decision_timeline) {
            html += `<div class="result-item"><p><strong>Decision Timeline:</strong></p>`;
            analysis.decision_timeline.forEach(step => {
                const icon = step.status === 'match' || step.status === 'high' || step.status === 'violation' ? '⚠️' : '✅';
                html += `
                    <div style="margin:5px 0; padding:5px; font-size:0.9rem;">
                        ${icon} Step ${step.step}: <strong>${step.agent}</strong> → ${step.result}
                    </div>
                `;
            });
            html += `</div>`;
        }
        
        // Framework Layers
        html += `
            <div class="result-item">
                <p><strong>Framework Layers:</strong></p>
                <div style="margin-top:5px">
                    <span class="layer-badge">Rule-Based: ${Math.round(analysis.layers.rule_based.score * 100)}%</span>
                    <span class="layer-badge">Semantic: ${Math.round(analysis.layers.semantic.score * 100)}%</span>
                    <span class="layer-badge">Policy: ${Math.round(analysis.layers.policy.score * 100)}%</span>
                </div>
            </div>
        `;
        
        // Agents Involved
        if (analysis.agents_involved) {
            html += `<div class="result-item"><p><strong>Agents Involved:</strong></p>`;
            analysis.agents_involved.forEach(agent => {
                const status = agent.active ? '✅' : '❌';
                html += `<div style="margin:3px 0;">${status} ${agent.name} (Confidence: ${Math.round(agent.confidence*100)}%)</div>`;
            });
            html += `</div>`;
        }
        
        // Metrics
        if (analysis.metrics) {
            html += `
                <div class="result-item">
                    <p><strong>Security Metrics:</strong></p>
                    <div style="font-size:0.9rem;">
                        Detection Confidence: ${analysis.metrics.detection_confidence}<br>
                        False Positive Risk: ${analysis.metrics.false_positive_risk}<br>
                        Framework Coverage: ${analysis.metrics.framework_coverage}
                    </div>
                </div>
            `;
        }
        
        html += `
            <div class="result-item">
                <p><strong>Explanation:</strong> ${analysis.explanation}</p>
            </div>
        `;
        
        frameworkAnalysisDetails.innerHTML = html;
    }

    // Helper function to format attack type names
    function formatAttackType(type) {
        return type
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }
    
    // Helper function to get CSS class based on risk level
    function getClassForRiskLevel(level) {
        switch(level.toLowerCase()) {
            case 'low': return 'low-risk';
            case 'medium': return 'medium-risk';
            case 'high': return 'high-risk';
            default: return '';
        }
    }
    
    // Helper function to escape HTML
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
});