class HeaderScanner {
    async analyzeHeaders(tab) {
        try {
            const results = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: async () => {
                    const response = await fetch(window.location.href);
                    const headers = response.headers;
                    let score = 100;
                    const findings = [];
                    const headerDetails = {};

                 
                    const securityHeaders = {
                        'Content-Security-Policy': {
                            required: true,
                            score: 15,
                            message: 'Content Security Policy (CSP) eksik',
                            checkValue: (value) => {
                                if (value.includes("'unsafe-inline'") || value.includes("'unsafe-eval'")) {
                                    return 'CSP yapılandırması güçlendirilmeli (unsafe-inline/eval kullanımı)';
                                }
                                return null;
                            }
                        },
                        'X-Frame-Options': {
                            required: true,
                            score: 15,
                            message: 'Clickjacking koruması (X-Frame-Options) eksik',
                            checkValue: (value) => {
                                if (!['DENY', 'SAMEORIGIN'].includes(value.toUpperCase())) {
                                    return 'X-Frame-Options değeri DENY veya SAMEORIGIN olmalı';
                                }
                                return null;
                            }
                        },
                        'X-Content-Type-Options': {
                            required: true,
                            score: 10,
                            message: 'MIME-type sniffing koruması eksik',
                            checkValue: (value) => {
                                if (value !== 'nosniff') {
                                    return 'X-Content-Type-Options değeri nosniff olmalı';
                                }
                                return null;
                            }
                        },
                        'Strict-Transport-Security': {
                            required: window.location.protocol === 'https:',
                            score: 15,
                            message: 'HSTS politikası eksik',
                            checkValue: (value) => {
                                const maxAge = value.match(/max-age=(\d+)/);
                                if (!maxAge || parseInt(maxAge[1]) < 31536000) {
                                    return 'HSTS max-age değeri en az 1 yıl olmalı';
                                }
                                return null;
                            }
                        },
                        'X-XSS-Protection': {
                            required: true,
                            score: 10,
                            message: 'XSS koruması eksik',
                            checkValue: (value) => {
                                if (value !== '1; mode=block') {
                                    return 'X-XSS-Protection değeri "1; mode=block" olmalı';
                                }
                                return null;
                            }
                        },
                        'Referrer-Policy': {
                            required: true,
                            score: 10,
                            message: 'Referrer Policy eksik',
                            checkValue: (value) => {
                                const safeValues = ['no-referrer', 'same-origin', 'strict-origin'];
                                if (!safeValues.includes(value)) {
                                    return 'Referrer Policy daha sıkı olmalı';
                                }
                                return null;
                            }
                        },
                        'Permissions-Policy': {
                            required: false,
                            score: 5,
                            message: 'Permissions Policy eksik',
                            checkValue: null
                        }
                    };

                 
                    for (const [header, config] of Object.entries(securityHeaders)) {
                        const headerValue = headers.get(header);
                        headerDetails[header] = headerValue || null;

                        if (!headerValue && config.required) {
                            score -= config.score;
                            findings.push(config.message);
                        } else if (headerValue && config.checkValue) {
                            const checkResult = config.checkValue(headerValue);
                            if (checkResult) {
                                score -= Math.floor(config.score / 2);
                                findings.push(checkResult);
                            }
                        }
                    }

                
                    const serverHeader = headers.get('Server');
                    if (serverHeader) {
                        headerDetails['Server'] = serverHeader;
                        if (serverHeader.match(/[\d.]+/)) {
                            score -= 10;
                            findings.push('Server header\'ı versiyon bilgisi içeriyor');
                        }
                    }

                  
                    const cookies = headers.get('Set-Cookie');
                    if (cookies) {
                        headerDetails['Set-Cookie'] = cookies;
                        const sensitiveNames = ['session', 'token', 'auth', 'key'];
                        const hasSensitiveCookie = sensitiveNames.some(name => 
                            cookies.toLowerCase().includes(name));

                        if (hasSensitiveCookie) {
                            if (!cookies.includes('Secure')) {
                                score -= 10;
                                findings.push('Hassas çerezler için Secure flag eksik');
                            }
                            if (!cookies.includes('HttpOnly')) {
                                score -= 10;
                                findings.push('Hassas çerezler için HttpOnly flag eksik');
                            }
                            if (!cookies.includes('SameSite')) {
                                score -= 5;
                                findings.push('Hassas çerezler için SameSite direktifi eksik');
                            }
                        }
                    }

                 
                    if (score < 60 && !findings.some(f => 
                        f.includes('Hassas') || f.includes('Clickjacking'))) {
                        score = Math.max(60, score);
                    }

                    return {
                        score: Math.max(0, score),
                        findings: findings.length > 0 ? findings : ['Header güvenlik kontrollerini geçti'],
                        details: headerDetails
                    };
                }
            });

            return ScannerUtils.formatScanResult(results[0].result);
        } catch (error) {
            console.error('Header analizi hatası:', error);
            return ScannerUtils.createEmptyResult();
        }
    }
}

window.HeaderScanner = HeaderScanner; 