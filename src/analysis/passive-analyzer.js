class PassiveAnalyzer {
    constructor() {
        this.securityScore = 0;
        this.findings = [];
        this.detailedResults = {};
        this.aiClient = new GroqAIClient();
    }

    async analyzeURL(tab) {
        try {
            const results = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => {
                    let score = 100;
                    const findings = [];
                    const details = {};

                   
                    const isHttps = window.location.protocol === 'https:';
                    details.protocol = window.location.protocol;

                    if (!isHttps) {
                       
                        const isLoginPage = document.querySelector('input[type="password"]') !== null;
                        const isAdminPage = window.location.pathname.includes('/admin');
                        
                        if (isLoginPage || isAdminPage) {
                            score -= 30;
                            findings.push('Hassas sayfa HTTP üzerinden sunuluyor (kritik güvenlik riski)');
                        } else {
                            score -= 15;
                            findings.push('Sayfa HTTPS kullanmıyor (önerilen)');
                        }
                    }

               
                    const urlParams = new URLSearchParams(window.location.search);
                    const sensitiveParams = ['token', 'key', 'auth', 'password', 'secret'];
                    
                    urlParams.forEach((value, key) => {
                  
                        if (sensitiveParams.some(param => key.toLowerCase().includes(param))) {
                            score -= 25;
                            findings.push(`URL'de hassas parametre tespit edildi: ${key}`);
                        }

                     
                        const sqlPatterns = [
                            /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b/i,
                            /'|"|;|\\/i
                        ];
                        if (sqlPatterns.some(pattern => pattern.test(value))) {
                            score -= 20;
                            findings.push(`Şüpheli SQL karakterleri: ${key} parametresinde`);
                        }

                    
                        const xssPatterns = [
                            /<[^>]*>/,
                            /javascript:/i,
                            /on\w+\s*=/i
                        ];
                        if (xssPatterns.some(pattern => pattern.test(value))) {
                            score -= 20;
                            findings.push(`Olası XSS riski: ${key} parametresinde`);
                        }
                    });

                  
                    const hostname = window.location.hostname;
                    if (hostname.split('.').length > 3) {
                     
                        findings.push('Subdomain kullanımı tespit edildi (güvenlik politikalarını kontrol edin)');
                    }

              
                    const port = window.location.port;
                    if (port && !['80', '443'].includes(port)) {
                        score -= 10;
                        findings.push(`Standart olmayan port kullanımı: ${port}`);
                    }

                
                    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
                    if (ipPattern.test(hostname)) {
                        score -= 15;
                        findings.push('IP adresi üzerinden erişim (domain kullanımı önerilir)');
                    }

               
                    const fragment = window.location.hash;
                    if (fragment && sensitiveParams.some(param => fragment.toLowerCase().includes(param))) {
                        score -= 15;
                        findings.push('URL fragment kısmında hassas veri');
                    }

          
                    const hasCriticalIssue = findings.some(f => 
                        f.includes('hassas') || f.includes('kritik'));

                    if (score < 70 && !hasCriticalIssue) {
                        score = Math.max(70, score);
                    }

           
                    const phishingChecks = {
                     
                        domainSimilarity: () => {
                            const popularDomains = [
                                'google', 'facebook', 'amazon', 'apple', 'microsoft',
                                'paypal', 'netflix', 'instagram', 'twitter', 'linkedin'
                            ];
                            
                            const domain = window.location.hostname.toLowerCase();
                            for (const popular of popularDomains) {
                                if (domain.includes(popular) && !domain.endsWith(`.${popular}.com`)) {
                                    score -= 30;
                                    findings.push(`Şüpheli domain: Popüler marka taklit edilmiş olabilir (${popular})`);
                                }
                            }
                        },

                     
                        loginFormCheck: () => {
                            const hasLoginForm = document.querySelector('input[type="password"]') !== null;
                            const isSecure = window.location.protocol === 'https:';
                            
                            if (hasLoginForm && !isSecure) {
                                score -= 30;
                                findings.push('Güvensiz login formu: HTTP kullanılıyor');
                            }
                        },

                   
                        suspiciousParams: () => {
                            const params = new URLSearchParams(window.location.search);
                            const suspiciousTerms = ['account', 'login', 'password', 'bank', 'verify'];
                            
                            suspiciousTerms.forEach(term => {
                                if (params.has(term)) {
                                    score -= 15;
                                    findings.push(`Şüpheli URL parametresi: ${term}`);
                                }
                            });
                        },

                   
                        contentCheck: () => {
                            const content = document.body.innerText.toLowerCase();
                            const redFlags = [
                                'verify your account',
                                'confirm your identity',
                                'update your payment',
                                'unusual activity',
                                'limited time offer',
                                'act now',
                                'urgent action required'
                            ];

                            redFlags.forEach(flag => {
                                if (content.includes(flag.toLowerCase())) {
                                    score -= 10;
                                    findings.push(`Şüpheli içerik tespit edildi: "${flag}"`);
                                }
                            });
                        },

               
                        sslCheck: () => {
                            const cert = document.querySelector('link[rel="canonical"]')?.href;
                            if (cert && !cert.startsWith('https://')) {
                                score -= 20;
                                findings.push('Güvensiz SSL yapılandırması');
                            }
                        }
                    };

                  
                    Object.values(phishingChecks).forEach(check => check());

                    return {
                        score: Math.max(0, score),
                        findings: findings.length > 0 ? findings : ['URL güvenlik kontrollerini geçti'],
                        details: {
                            protocol: details.protocol,
                            hostname: hostname,
                            parameterCount: urlParams.size,
                            hasSubdomain: hostname.split('.').length > 3,
                            phishingScore: score
                        }
                    };
                }
            });

            return ScannerUtils.formatScanResult(results[0].result);
        } catch (error) {
            console.error('URL analizi hatası:', error);
            return ScannerUtils.createEmptyResult();
        }
    }

    checkHTTPSProtocol(url) {
        const urlObj = new URL(url);
        return {
            status: urlObj.protocol === 'https:',
            message: urlObj.protocol === 'https:' ? 
                'HTTPS protokolü kullanılıyor' : 
                'Güvensiz HTTP protokolü tespit edildi'
        };
    }

    async checkSSLCertificate(url) {
        try {
          
            if (url.startsWith('chrome://')) {
                return {
                    status: false,
                    message: 'Chrome URL\'leri analiz edilemez'
                };
            }

            const response = await fetch(url);
            const cert = response.headers.get('strict-transport-security');
            return {
                status: !!cert,
                message: cert ? 'SSL sertifikası aktif' : 'SSL sertifikası bulunamadı'
            };
        } catch (error) {
            return {
                status: false,
                message: 'SSL sertifikası kontrol edilemedi'
            };
        }
    }

    checkSuspiciousURLPatterns(url) {
        const suspiciousPatterns = [
            {
                pattern: /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/,
                description: 'IP adresi içeren URL'
            },
            {
                pattern: /(password|login|secure|account|banking)/i,
                description: 'Hassas kelimeler içeren URL'
            },
            {
                pattern: /[а-яА-Я]/,
                description: 'Kiril alfabesi içeren URL'
            },
            {
                pattern: /@/,
                description: 'URL içinde @ işareti'
            },
            {
                pattern: /\.(tk|ml|ga|cf|gq)$/i,
                description: 'Ücretsiz domain uzantısı'
            }
        ];

        const findings = suspiciousPatterns
            .filter(p => p.pattern.test(url))
            .map(p => p.description);

        return {
            status: findings.length === 0,
            message: findings.length === 0 ? 
                'Şüpheli URL patternı bulunamadı' : 
                'Şüpheli URL patternları tespit edildi',
            findings
        };
    }

    updateSecurityScore(checks) {
        let score = 100;
        
    
        if (!checks.isHTTPS.status) score -= 30;
        
        
        if (!checks.validSSL.status) score -= 25;
        
    
        if (checks.domainReputation.status === false) score -= 25;
        
  
        if (!checks.suspiciousPatterns.status) {
            score -= (checks.suspiciousPatterns.findings.length * 5);
        }

        this.securityScore = Math.max(0, score);
        return this.securityScore;
    }

    async performDNSChecks(url) {
        const domain = new URL(url).hostname;
        try {
            const dnsPromises = [
                this.checkDNSSEC(domain),
                this.checkCAA(domain),
                this.checkMXRecords(domain),
                this.checkSPFRecord(domain),
                this.checkDMARCRecord(domain)
            ];

            const [dnssec, caa, mx, spf, dmarc] = await Promise.all(dnsPromises);

            return {
                dnssec,
                caa,
                mx,
                spf,
                dmarc,
                score: this.calculateDNSScore({dnssec, caa, mx, spf, dmarc})
            };
        } catch (error) {
            return {
                error: 'DNS kontrolleri yapılamadı',
                score: 0
            };
        }
    }

    async getDetailedSSLInfo(url) {
        try {
           
            if (url.startsWith('chrome://')) {
                return {
                    error: 'Chrome URL\'leri analiz edilemez'
                };
            }

            const response = await fetch(url);
            const cert = response.headers;
            
            return {
                hsts: this.checkHSTS(cert),
                certTransparency: this.checkCertificateTransparency(cert),
                keyExchange: this.checkKeyExchange(cert),
                cipherSuite: this.checkCipherSuite(cert),
                certChain: await this.verifyCertificateChain(url),
                revocationStatus: await this.checkCertRevocationStatus(url)
            };
        } catch (error) {
            return {
                error: 'SSL detaylı analizi yapılamadı'
            };
        }
    }

    checkHSTS(headers) {
        const hstsHeader = headers.get('strict-transport-security');
        if (!hstsHeader) return { status: false, message: 'HSTS bulunamadı' };

        const maxAge = hstsHeader.match(/max-age=(\d+)/);
        const includesSubDomains = hstsHeader.includes('includeSubDomains');
        const preload = hstsHeader.includes('preload');

        return {
            status: true,
            maxAge: maxAge ? parseInt(maxAge[1]) : 0,
            includesSubDomains,
            preload,
            score: this.calculateHSTSScore({maxAge: maxAge?.[1], includesSubDomains, preload})
        };
    }

    async checkPublicSubdomains(url) {
        const domain = new URL(url).hostname;
        try {
            const response = await fetch(`https://crt.sh/?q=${domain}&output=json`);
            const certs = await response.json();
            
            const subdomains = new Set();
            certs.forEach(cert => {
                const names = cert.name_value.split('\n');
                names.forEach(name => {
                    if (name.endsWith(domain) && name !== domain) {
                        subdomains.add(name);
                    }
                });
            });

            return {
                count: subdomains.size,
                list: Array.from(subdomains),
                riskLevel: this.assessSubdomainRisk(subdomains.size)
            };
        } catch (error) {
            return {
                error: 'Subdomain analizi yapılamadı',
                count: 0,
                list: []
            };
        }
    }

    calculateDNSScore(checks) {
        let score = 100;
        if (!checks.dnssec) score -= 20;
        if (!checks.caa) score -= 15;
        if (!checks.spf) score -= 15;
        if (!checks.dmarc) score -= 15;
        if (!checks.mx) score -= 10;
        return Math.max(0, score);
    }

    assessSubdomainRisk(count) {
        if (count > 100) return 'YÜKSEK';
        if (count > 50) return 'ORTA';
        if (count > 20) return 'DÜŞÜK';
        return 'MİNİMAL';
    }

    async generateAIPrompt(findings) {
        const prompt = `Web Güvenlik Analizi:

URL: ${window.location.href}

Tespit Edilen Güvenlik Sorunları:
${findings.map(f => `- ${f}`).join('\n')}

Lütfen aşağıdaki başlıklar için kısa ve öz öneriler ver:

1. Risk Seviyesi: Bu sorunların genel risk seviyesini değerlendir (Yüksek/Orta/Düşük)
2. Öncelikli Tehditler: En kritik 2-3 güvenlik açığını belirt
3. Hızlı Çözümler: Her bir kritik sorun için tek cümlelik çözüm önerisi
4. Uzun Vadeli Öneriler: Genel güvenlik duruşunu iyileştirmek için 2-3 stratejik öneri

Not: Lütfen teknik detaylara girmeden, yönetici seviyesinde anlaşılır öneriler ver.`;

        return prompt;
    }

    async processAIRecommendations(response) {
        try {
            let recommendations = [];
            
            if (typeof response === 'string') {
                const sections = response.split('\n\n');
                
                sections.forEach(section => {
                    if (section.trim().length > 0) {
                        recommendations.push({
                            text: section.trim()
                        });
                    }
                });
            } else if (response?.content?.choices?.[0]?.message?.content) {
                const content = response.content.choices[0].message.content;
                recommendations = [{
                    text: content
                }];
            }

            return recommendations;
        } catch (error) {
            console.error('AI tavsiyeleri işlenirken hata:', error);
            return [{
                text: 'AI tavsiyeleri işlenirken bir hata oluştu. Lütfen daha sonra tekrar deneyin.'
            }];
        }
    }

    calculateSecurityScore(findings) {
        let score = 100;
        
        const criticalIssues = [
            'HTTP kullanımı',
            'Hassas veri',
            'XSS koruması yok',
            'SQL Injection riski',
            'CSP eksik'
        ];

        const mediumIssues = [
            'Çerez güvenliği',
            'Form güvenliği',
            'Header eksik',
            'Meta tag eksik'
        ];

        const lowIssues = [
            'Önerilen header',
            'Önerilen meta tag',
            'İyileştirme önerisi'
        ];

        findings.forEach(finding => {
            if (criticalIssues.some(issue => finding.toLowerCase().includes(issue.toLowerCase()))) {
                score -= 20;
            } else if (mediumIssues.some(issue => finding.toLowerCase().includes(issue.toLowerCase()))) {
                score -= 10;
            } else if (lowIssues.some(issue => finding.toLowerCase().includes(issue.toLowerCase()))) {
                score -= 5;
            }
        });

        return Math.max(0, score); 
    }
}

window.PassiveAnalyzer = PassiveAnalyzer; 