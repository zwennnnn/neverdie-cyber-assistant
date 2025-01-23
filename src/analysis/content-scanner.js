
class ContentScanner {
    constructor() {
        this.findings = [];
        this.score = 100;
    }

    async analyzeContent(tab) {
        try {
            const results = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => {
                    let score = 100;
                    const findings = [];
                    
              
                    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                    const cspHeader = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                    
                    if (!cspMeta && !cspHeader) {
                        score -= 30;
                        findings.push('Content Security Policy (CSP) eksik');
                    }

            
                    if (!document.querySelector('meta[http-equiv="X-XSS-Protection"]')) {
                        score -= 20;
                        findings.push('X-XSS-Protection header eksik');
                    }

              
                    if (!document.querySelector('meta[http-equiv="X-Frame-Options"]')) {
                        score -= 20;
                        findings.push('X-Frame-Options header eksik');
                    }

             
                    if (!document.querySelector('meta[name="referrer"]')) {
                        score -= 15;
                        findings.push('Referrer Policy tanımlanmamış');
                    }

                    return {
                        score: Math.max(0, score),
                        findings: findings.length > 0 ? findings : ['İçerik güvenliği iyi durumda']
                    };
                }
            });

            return results[0].result;
        } catch (error) {
            console.error('Content analizi hatası:', error);
            return {
                score: 0,
                findings: ['İçerik analizi yapılamadı: ' + error.message]
            };
        }
    }

    async getSecurityHeaders(tab) {
        return new Promise((resolve) => {
            chrome.webRequest.onHeadersReceived.addListener(
                (details) => {
                    const headers = {};
                    details.responseHeaders.forEach(header => {
                        if (this.isSecurityHeader(header.name)) {
                            headers[header.name.toLowerCase()] = header.value;
                        }
                    });
                    resolve(headers);
                },
                { urls: [tab.url], types: ['main_frame'] },
                ['responseHeaders']
            );
        });
    }

    isSecurityHeader(headerName) {
        const securityHeaders = [
            'content-security-policy',
            'x-content-security-policy',
            'x-webkit-csp',
            'x-frame-options',
            'x-xss-protection',
            'strict-transport-security',
            'x-content-type-options'
        ];
        return securityHeaders.includes(headerName.toLowerCase());
    }

    analyzeCSPHeaders(headers) {
        let score = 0;
        const findings = [];
        const csp = headers['content-security-policy'];

        if (!csp) {
            findings.push('CSP header bulunamadı');
            return { score: 0, findings };
        }

       
        const directives = {
            'default-src': 10,
            'script-src': 15,
            'style-src': 10,
            'img-src': 10,
            'connect-src': 10,
            'font-src': 5,
            'object-src': 10,
            'media-src': 5,
            'frame-src': 10,
            'sandbox': 5,
            'report-uri': 5,
            'form-action': 5
        };

        Object.keys(directives).forEach(directive => {
            if (csp.includes(directive)) {
                score += directives[directive];
                findings.push(`${directive} direktifi mevcut`);
            } else {
                findings.push(`${directive} direktifi eksik`);
            }
        });

     
        if (csp.includes("'unsafe-inline'")) {
            score -= 15;
            findings.push("Güvensiz inline script/style kullanımı tespit edildi");
        }
        if (csp.includes("'unsafe-eval'")) {
            score -= 15;
            findings.push("Güvensiz eval kullanımı tespit edildi");
        }

        return {
            score: Math.max(0, Math.min(100, score)),
            findings
        };
    }
}


window.ContentScanner = ContentScanner; 