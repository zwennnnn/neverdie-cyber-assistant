class FormScanner {
    constructor() {
        this.findings = [];
    }

    async analyzeForms(tab) {
        try {
            const results = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => {
                    const forms = document.getElementsByTagName('form');
                    let score = 100;
                    const findings = [];
                    const formDetails = [];

                    if (!document || forms.length === 0) {
                        return {
                            score: 100,
                            findings: ['Sayfada form elementi bulunamadı'],
                            formCount: 0,
                            details: []
                        };
                    }

                    Array.from(forms).forEach((form, index) => {
                        const formId = form.id || `Form #${index + 1}`;
                        
                       
                        const hasPasswordField = form.querySelector('input[type="password"]');
                        const hasSensitiveData = form.querySelector('input[type="credit-card"], input[name*="credit"], input[name*="card"]');
                        
                        if ((hasPasswordField || hasSensitiveData) && !form.action.startsWith('https://')) {
                            score -= 30;
                            findings.push(`${formId}: Hassas veri içeren form HTTPS kullanmıyor`);
                        }

                      
                        if (form.method.toUpperCase() === 'POST' && 
                            (hasPasswordField || form.action.includes('/login') || form.action.includes('/register'))) {
                            const hasCSRFToken = !!form.querySelector('input[name*="csrf"], input[name*="token"]');
                            if (!hasCSRFToken) {
                                score -= 20;
                                findings.push(`${formId}: Önemli form işlemi için CSRF koruması eksik`);
                            }
                        }

                  
                        const criticalInputs = form.querySelectorAll('input[type="email"], input[type="password"], input[type="tel"]');
                        criticalInputs.forEach(input => {
                            if (!input.hasAttribute('required') || 
                                !input.hasAttribute('pattern') && input.type === 'email') {
                                score -= 5;
                                findings.push(`${formId}: ${input.type} alanı için validasyon eksik`);
                            }
                        });

                    
                        const sensitiveInputs = form.querySelectorAll('input[type="password"], input[name*="card"]');
                        sensitiveInputs.forEach(input => {
                            if (!input.hasAttribute('autocomplete')) {
                                score -= 5;
                                findings.push(`${formId}: Hassas alan için autocomplete özelliği eksik`);
                            }
                        });

                        formDetails.push({
                            id: formId,
                            action: form.action,
                            method: form.method,
                            hasSensitiveData: hasPasswordField || hasSensitiveData,
                            inputCount: form.getElementsByTagName('input').length
                        });
                    });

            
                    if (score < 60 && !findings.some(f => f.includes('Hassas veri'))) {
                        score = Math.max(60, score);
                    }

                    return {
                        score: Math.max(0, score),
                        findings: findings.length > 0 ? findings : ['Form güvenlik kontrollerini geçti'],
                        formCount: forms.length,
                        details: formDetails
                    };
                }
            });

            if (!results || !results[0] || !results[0].result) {
                return ScannerUtils.createEmptyResult();
            }

            return ScannerUtils.formatScanResult(results[0].result);
        } catch (error) {
            console.error('Form analizi hatası:', error);
            return ScannerUtils.createEmptyResult();
        }
    }

    scanFormElements() {
        const forms = document.getElementsByTagName('form');
        let score = 100;
        const findings = [];
        
   
        const xssChecks = { score: 100, findings: [] };
        const csrfChecks = { score: 100, findings: [] };
        const validationChecks = { score: 100, findings: [] };
        const sensitiveDataChecks = { score: 100, findings: [] };
        const accessibilityChecks = { score: 100, findings: [] };

        if (forms.length === 0) {
            return {
                score: 100,
                findings: ['Sayfada form elementi bulunamadı'],
                xssChecks, csrfChecks, validationChecks, 
                sensitiveDataChecks, accessibilityChecks
            };
        }

        Array.from(forms).forEach((form, index) => {
            
            this.checkXSSProtection(form, xssChecks);
            
       
            this.checkCSRFProtection(form, csrfChecks);
            
        
            this.checkInputValidation(form, validationChecks);
            
          
            this.checkSensitiveDataHandling(form, sensitiveDataChecks);
            
      
            this.checkAccessibility(form, accessibilityChecks);
        });

 
        score = this.calculateOverallScore({
            xssChecks, csrfChecks, validationChecks, 
            sensitiveDataChecks, accessibilityChecks
        });

        return {
            score,
            findings: [
                ...xssChecks.findings,
                ...csrfChecks.findings,
                ...validationChecks.findings,
                ...sensitiveDataChecks.findings,
                ...accessibilityChecks.findings
            ],
            xssChecks,
            csrfChecks,
            validationChecks,
            sensitiveDataChecks,
            accessibilityScore: accessibilityChecks.score
        };
    }

    checkXSSProtection(form, checks) {
  
        const inputs = form.getElementsByTagName('input');
        Array.from(inputs).forEach(input => {
            if (!input.pattern && ['text', 'search', 'url', 'tel', 'email'].includes(input.type)) {
                checks.score -= 10;
                checks.findings.push(`XSS: Pattern validasyonu eksik (${input.name || 'isimsiz input'})`);
            }
        });

    
        const scripts = form.getElementsByTagName('script');
        Array.from(scripts).forEach(script => {
            if (script.textContent.includes('innerHTML')) {
                checks.score -= 20;
                checks.findings.push('XSS: Güvensiz innerHTML kullanımı tespit edildi');
            }
        });
    }

    calculateOverallScore(checks) {
        return Math.floor(
            (checks.xssChecks.score * 0.25) +
            (checks.csrfChecks.score * 0.25) +
            (checks.validationChecks.score * 0.20) +
            (checks.sensitiveDataChecks.score * 0.20) +
            (checks.accessibilityChecks.score * 0.10)
        );
    }

    generateSummaryMessage(score) {
        if (score >= 90) {
            return 'Form güvenliği çok iyi durumda';
        } else if (score >= 70) {
            return 'Form güvenliği kabul edilebilir seviyede, bazı iyileştirmeler yapılabilir';
        } else if (score >= 50) {
            return 'Form güvenliğinde önemli eksiklikler mevcut';
        } else {
            return 'Form güvenliği kritik seviyede düşük';
        }
    }
}

window.FormScanner = FormScanner; 