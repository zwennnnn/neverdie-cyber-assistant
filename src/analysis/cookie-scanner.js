class CookieScanner {
    constructor() {
        this.findings = [];
        this.aiClient = new GroqAIClient();
    }

    async analyzeCookies(tab) {
        try {
            const results = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => {
                    let score = 100;
                    const findings = [];
                    const cookieDetails = {};

              
                    const cookies = document.cookie.split(';').map(c => c.trim());
                    
                 
                    if (cookies.length === 0 || (cookies.length === 1 && cookies[0] === '')) {
                        return {
                            score: 100,
                            findings: ['Sayfada çerez kullanımı tespit edilmedi'],
                            details: { cookieCount: 0 }
                        };
                    }

              
                    const sensitiveCookies = [
                        'session', 'token', 'auth', 'key', 'password', 
                        'secret', 'csrf', 'admin', 'login'
                    ];

                    cookies.forEach(cookie => {
                        const [name, value] = cookie.split('=').map(s => s.trim());
                        cookieDetails[name] = {
                            hasSecure: cookie.toLowerCase().includes('secure'),
                            hasHttpOnly: cookie.toLowerCase().includes('httponly'),
                            hasSameSite: cookie.toLowerCase().includes('samesite'),
                            isSensitive: sensitiveCookies.some(s => name.toLowerCase().includes(s))
                        };

                     
                        if (cookieDetails[name].isSensitive) {
                            if (!cookieDetails[name].hasSecure) {
                                score -= 15;
                                findings.push(`Hassas çerez (${name}) için Secure flag eksik`);
                            }
                            if (!cookieDetails[name].hasHttpOnly) {
                                score -= 15;
                                findings.push(`Hassas çerez (${name}) için HttpOnly flag eksik`);
                            }
                            if (!cookieDetails[name].hasSameSite) {
                                score -= 10;
                                findings.push(`Hassas çerez (${name}) için SameSite özelliği eksik`);
                            }
                        } else {
                         
                            if (!cookieDetails[name].hasSecure && window.location.protocol === 'https:') {
                                score -= 5;
                                findings.push(`${name} çerezi için Secure flag önerilir`);
                            }
                            if (!cookieDetails[name].hasSameSite) {
                                score -= 5;
                                findings.push(`${name} çerezi için SameSite önerilir`);
                            }
                        }

                      
                        if (value.length > 100) {
                            const sensitivePatterns = [
                                /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/,
                                /[A-Za-z0-9+/=]{40,}/ 
                            ];
                            if (sensitivePatterns.some(p => p.test(value))) {
                                score -= 10;
                                findings.push(`${name} çerezinde hassas veri olabilir`);
                            }
                        }
                    });

                    
                    const hasConsentCookie = cookies.some(c => 
                        c.toLowerCase().includes('consent') || 
                        c.toLowerCase().includes('gdpr') || 
                        c.toLowerCase().includes('kvkk'));

                    if (!hasConsentCookie) {
                        score -= 5;
                        findings.push('Çerez onay mekanizması tespit edilemedi');
                    }

                
                    const hasCriticalIssue = findings.some(f => 
                        f.includes('Hassas çerez') && 
                        (f.includes('Secure') || f.includes('HttpOnly')));

                    if (score < 70 && !hasCriticalIssue) {
                        score = Math.max(70, score);
                    }

                    return {
                        score: Math.max(0, score),
                        findings: findings.length > 0 ? findings : ['Çerez güvenlik kontrollerini geçti'],
                        details: {
                            cookieCount: cookies.length,
                            cookies: cookieDetails
                        }
                    };
                }
            });

            return ScannerUtils.formatScanResult(results[0].result);
        } catch (error) {
            console.error('Çerez analizi hatası:', error);
            return ScannerUtils.createEmptyResult();
        }
    }

    async getCookies(url) {
        return new Promise((resolve) => {
            chrome.cookies.getAll({ url }, (cookies) => {
                resolve(cookies || []);
            });
        });
    }

    async checkCookiePolicy(tab) {
        const findings = [];
        try {
           
            const result = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                function: () => {
                    const cookieTerms = ['cookie', 'çerez', 'gdpr', 'kvkk'];
                    const elements = document.body.innerHTML.toLowerCase();
                    
                    const hasCookieBanner = cookieTerms.some(term => 
                        elements.includes(term));
                    
                    const hasCookiePolicy = document.querySelector(
                        'a[href*="cookie"], a[href*="cerez"], a[href*="gizlilik"]'
                    );

                    return { hasCookieBanner, hasCookiePolicy: !!hasCookiePolicy };
                }
            });

            const { hasCookieBanner, hasCookiePolicy } = result[0].result;

            if (!hasCookieBanner) {
                findings.push('Çerez bildirimi (cookie banner) bulunamadı');
            }
            if (!hasCookiePolicy) {
                findings.push('Çerez politikası sayfası bulunamadı');
            }

            return { findings };
        } catch (error) {
            findings.push('Çerez politikası kontrolü yapılamadı');
            return { findings };
        }
    }

    analyzeCookieSecurityFeatures(cookies) {
        let score = 100;
        const findings = [];

        cookies.forEach(cookie => {
           
            if (!cookie.secure) {
                score -= 15;
                findings.push(`${cookie.name} çerezi için Secure bayrağı eksik`);
            }

        
            if (!cookie.httpOnly) {
                score -= 10;
                findings.push(`${cookie.name} çerezi için HttpOnly bayrağı eksik`);
            }

     
            if (!cookie.sameSite || cookie.sameSite === 'None') {
                score -= 10;
                findings.push(`${cookie.name} çerezi için SameSite özelliği eksik veya None`);
            }

       
            const expirationDate = new Date(cookie.expirationDate * 1000);
            const oneYearFromNow = new Date();
            oneYearFromNow.setFullYear(oneYearFromNow.getFullYear() + 1);

            if (expirationDate > oneYearFromNow) {
                score -= 5;
                findings.push(`${cookie.name} çerezinin süresi bir yıldan fazla`);
            }
        });

        return {
            score: Math.max(0, score),
            findings
        };
    }

    generateSummaryMessage(score) {
        if (score >= 90) {
            return 'Çerez güvenliği ve uyumluluğu çok iyi durumda';
        } else if (score >= 70) {
            return 'Çerez güvenliği kabul edilebilir seviyede, bazı iyileştirmeler yapılabilir';
        } else if (score >= 50) {
            return 'Çerez güvenliğinde önemli eksiklikler mevcut';
        } else {
            return 'Çerez güvenliği kritik seviyede düşük';
        }
    }
}

window.CookieScanner = CookieScanner; 