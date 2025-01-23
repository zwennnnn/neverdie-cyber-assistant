class ScannerUtils {
    static async fetchWithTimeout(url, options = {}, timeout = 5000) {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(id);
            return response;
        } catch (error) {
            clearTimeout(id);
            throw error;
        }
    }

    static calculateRiskScore(findings, weights = {}) {
        const defaultWeights = {
            critical: 1.0,
            high: 0.8,
            medium: 0.5,
            low: 0.3,
            info: 0.1
        };

        const finalWeights = { ...defaultWeights, ...weights };
        let totalScore = 100;

        findings.forEach(finding => {
            const severity = this.determineSeverity(finding);
            totalScore -= (finding.impact || 10) * finalWeights[severity];
        });

        return Math.max(0, Math.min(100, Math.round(totalScore)));
    }

    static determineSeverity(finding) {
        const text = finding.toLowerCase();
        if (text.includes('kritik') || text.includes('yüksek risk')) return 'critical';
        if (text.includes('yüksek')) return 'high';
        if (text.includes('orta')) return 'medium';
        if (text.includes('düşük')) return 'low';
        return 'info';
    }

    static sanitizeOutput(text) {
        return text.replace(/[<>'"]/g, '');
    }

    static async validateCertificate(url) {
        try {
            const response = await this.fetchWithTimeout(url);
            const cert = response.headers.get('strict-transport-security');
            return {
                valid: !!cert,
                details: cert ? this.parseCertificateDetails(cert) : null
            };
        } catch (error) {
            return { valid: false, error: error.message };
        }
    }

    static parseCertificateDetails(cert) {
        const details = {};
        cert.split(';').forEach(part => {
            const [key, value] = part.trim().split('=');
            details[key] = value || true;
        });
        return details;
    }

    static generateReportSummary(results) {
        return {
            timestamp: new Date().toISOString(),
            overallScore: this.calculateOverallScore(results),
            criticalFindings: this.extractCriticalFindings(results),
            recommendations: this.generateRecommendations(results)
        };
    }

    static calculateOverallScore(results) {
        const scores = Object.values(results).map(r => r.score || 0);
        return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    }

    static extractCriticalFindings(results) {
        return Object.values(results)
            .flatMap(r => r.findings || [])
            .filter(f => this.determineSeverity(f) === 'critical');
    }

    static generateRecommendations(results) {
        return Object.values(results)
            .flatMap(r => r.recommendations || [])
            .sort((a, b) => this.getSeverityWeight(b) - this.getSeverityWeight(a));
    }

    static getSeverityWeight(recommendation) {
        const weights = { critical: 4, high: 3, medium: 2, low: 1 };
        return weights[recommendation.priority.toLowerCase()] || 0;
    }

    static formatScanResult(data) {
        if (!data) {
            return this.createEmptyResult();
        }

        return {
            score: typeof data.score === 'number' ? data.score : 0,
            findings: Array.isArray(data.findings) ? data.findings : ['Analiz sonucu alınamadı'],
            error: data.error || false,
            message: data.message || '',
            details: data.details || {}
        };
    }

    static createEmptyResult() {
        return {
            score: 0,
            findings: ['Analiz yapılamadı'],
            error: true,
            message: 'Analiz başarısız',
            details: {}
        };
    }

    static async checkDomain(domain) {
        try {
            const response = await this.fetchWithTimeout(`https://dns.google/resolve?name=${domain}`);
            const data = await response.json();
            return {
                exists: data.Status === 0,
                secure: data.AD === true, 
                records: data.Answer || []
            };
        } catch (error) {
            return { error: true, message: error.message };
        }
    }

    static async checkSSL(url) {
        try {
            const response = await this.fetchWithTimeout(url);
            const cert = response.headers.get('strict-transport-security');
            return {
                hasSSL: url.startsWith('https'),
                hasHSTS: !!cert,
                details: cert ? this.parseHSTS(cert) : null
            };
        } catch (error) {
            return { error: true, message: error.message };
        }
    }

    static parseHSTS(header) {
        const details = {};
        header.split(';').forEach(part => {
            const [key, value] = part.trim().split('=');
            details[key] = value || true;
        });
        return details;
    }

    static async checkHeaders(headers) {
        const securityHeaders = {
            'Content-Security-Policy': false,
            'X-Frame-Options': false,
            'X-XSS-Protection': false,
            'X-Content-Type-Options': false,
            'Referrer-Policy': false,
            'Permissions-Policy': false
        };

        for (const [header, value] of headers.entries()) {
            if (header.toLowerCase() in securityHeaders) {
                securityHeaders[header] = true;
            }
        }

        return securityHeaders;
    }

    static checkFormSecurity(form) {
        const checks = {
            method: form.method.toUpperCase(),
            action: form.action,
            hasCSRF: false,
            hasEnctype: false,
            inputValidation: true,
            secureTransport: false
        };

      
        const csrfToken = form.querySelector('input[name*="csrf"]');
        checks.hasCSRF = !!csrfToken;

   
        checks.hasEnctype = form.enctype === 'multipart/form-data';

      
        checks.secureTransport = form.action.startsWith('https://');

        const inputs = form.querySelectorAll('input');
        inputs.forEach(input => {
            if (!input.hasAttribute('pattern') && 
                !input.hasAttribute('required') && 
                !input.hasAttribute('minlength')) {
                checks.inputValidation = false;
            }
        });

        return checks;
    }

    static checkCookieSecurity(cookie) {
        return {
            hasSecure: cookie.includes('Secure'),
            hasHttpOnly: cookie.includes('HttpOnly'),
            hasSameSite: cookie.includes('SameSite'),
            sameSiteValue: cookie.match(/SameSite=(Lax|Strict|None)/) ? 
                          cookie.match(/SameSite=(Lax|Strict|None)/)[1] : null
        };
    }

    static checkContentSecurity(content) {
        return {
            hasInlineJS: /<script>.*?<\/script>/i.test(content),
            hasInlineCSS: /<style>.*?<\/style>/i.test(content),
            hasEval: /eval\(.*?\)/i.test(content),
            hasInnerHTML: /innerHTML.*?=/i.test(content),
            hasDocumentWrite: /document\.write/i.test(content)
        };
    }
}


window.ScannerUtils = ScannerUtils; 