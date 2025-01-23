class MetaScanner {
    constructor() {
        this.findings = [];
        this.aiClient = new GroqAIClient();
    }

    async analyzeMetaTags(tab) {
        try {
            const results = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => {
                    let score = 100;
                    const findings = [];
                    const metaDetails = {};
                    
                    const metaTags = document.getElementsByTagName('meta');
                    
                    const securityMeta = {
                        'Content-Security-Policy': {
                            found: false,
                            required: false,
                            score: 10,
                            message: 'CSP meta etiketi eksik'
                        },
                        'X-Frame-Options': {
                            found: false,
                            required: false,
                            score: 10,
                            message: 'X-Frame-Options meta etiketi eksik'
                        },
                        'charset': {
                            found: false,
                            required: true,
                            score: 15,
                            message: 'Karakter seti (charset) tanımlanmamış'
                        }
                    };

                
                    Array.from(metaTags).forEach(meta => {
                        const name = meta.getAttribute('name')?.toLowerCase();
                        const httpEquiv = meta.getAttribute('http-equiv')?.toLowerCase();
                        const content = meta.getAttribute('content');
                        const charset = meta.getAttribute('charset');

                        metaDetails[name || httpEquiv || 'charset'] = content || charset;

                
                        if (charset || httpEquiv === 'content-type') {
                            securityMeta['charset'].found = true;
                            const charsetValue = charset || content?.match(/charset=([\w-]+)/i)?.[1];
                            if (charsetValue && charsetValue.toLowerCase() !== 'utf-8') {
                                score -= 5;
                                findings.push('UTF-8 dışında karakter seti kullanılıyor');
                            }
                        }

                     
                        const sensitiveTerms = ['password', 'token', 'api-key', 'secret'];
                        if (content && sensitiveTerms.some(term => content.toLowerCase().includes(term))) {
                            score -= 20;
                            findings.push('Meta etiketlerinde hassas bilgi tespit edildi');
                        }

                   
                        if (name === 'robots' && 
                            (window.location.pathname.includes('/admin') || 
                             window.location.pathname.includes('/dashboard'))) {
                            if (!content?.includes('noindex')) {
                                score -= 15;
                                findings.push('Hassas sayfa için robots meta etiketi eksik');
                            }
                        }

                     
                        if (name === 'generator' && content?.match(/\d+\.\d+/)) {
                            score -= 5;
                            findings.push('Generator meta etiketi versiyon bilgisi içeriyor');
                        }
                    });

               
                    Object.entries(securityMeta).forEach(([name, config]) => {
                        if (config.required && !config.found) {
                            score -= config.score;
                            findings.push(config.message);
                        }
                    });

            
                    if (score < 70 && !findings.some(f => f.includes('hassas bilgi'))) {
                        score = Math.max(70, score);
                    }

                    return {
                        score: Math.max(0, score),
                        findings: findings.length > 0 ? findings : ['Meta etiketleri güvenlik kontrollerini geçti'],
                        details: {
                            metaTags: metaDetails,
                            securityMetaStatus: securityMeta
                        }
                    };
                }
            });

            return ScannerUtils.formatScanResult(results[0].result);
        } catch (error) {
            console.error('Meta tag analizi hatası:', error);
            return ScannerUtils.createEmptyResult();
        }
    }

    async getGroqSecurityAdvice(analysis) {
        try {
            const prompt = `
                Aşağıdaki meta tag güvenlik analizi sonuçlarına göre, 
                en kritik 3 güvenlik tavsiyesi ver ve öncelik sırasına göre sırala:
                
                Genel Skor: ${analysis.score}
                CSP Skoru: ${analysis.cspAnalysis.score}
                Gizlilik Skoru: ${analysis.privacyAnalysis.score}
                
                Tespit edilen sorunlar:
                ${analysis.findings.join('\n')}
                
                Lütfen tavsiyeleri şu formatta ver:
                1. [KRİTİK] - İlk tavsiye
                2. [ORTA] - İkinci tavsiye
                3. [DÜŞÜK] - Üçüncü tavsiye
            `;

            const response = await this.groqClient.chat.completions.create({
                messages: [{ role: 'user', content: prompt }],
                model: 'mixtral-8x7b-32768',
                temperature: 0.3,
                max_tokens: 500
            });

            return response.choices[0].message.content;
        } catch (error) {
            return ['Groq API ile bağlantı kurulamadı'];
        }
    }

    async getGroqSEOSecurityAdvice(analysis) {
        try {
            const prompt = `
                Aşağıdaki SEO güvenlik analizi sonuçlarına göre, 
                SEO açısından güvenlik tavsiyeleri ver:
                
                SEO Güvenlik Skoru: ${analysis.seoAnalysis.score}
                
                Tespit edilen SEO güvenlik sorunları:
                ${analysis.seoAnalysis.findings.join('\n')}
                
                Lütfen şu konulara odaklan:
                1. Bilgi sızıntısı riski
                2. SEO zafiyetleri
                3. Crawler güvenliği
                4. Meta veri güvenliği
            `;

            const response = await this.groqClient.chat.completions.create({
                messages: [{ role: 'user', content: prompt }],
                model: 'mixtral-8x7b-32768',
                temperature: 0.3,
                max_tokens: 500
            });

            return response.choices[0].message.content;
        } catch (error) {
            return ['SEO güvenlik tavsiyeleri alınamadı'];
        }
    }

    scanMetaElements() {
        let score = 100;
        const findings = [];
        const metaTags = document.getElementsByTagName('meta');

     
        const cspTag = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        if (!cspTag) {
            score -= 20;
            findings.push('Content Security Policy meta etiketi bulunamadı');
        } else {
            const cspContent = cspTag.getAttribute('content');
            if (!cspContent.includes("default-src 'self'")) {
                score -= 10;
                findings.push('CSP default-src politikası eksik veya güvensiz');
            }
        }

        const xFrameTag = document.querySelector('meta[http-equiv="X-Frame-Options"]');
        if (!xFrameTag) {
            score -= 15;
            findings.push('X-Frame-Options meta etiketi bulunamadı (Clickjacking koruması eksik)');
        }

        const charsetTag = document.querySelector('meta[charset]');
        if (!charsetTag || charsetTag.getAttribute('charset').toLowerCase() !== 'utf-8') {
            score -= 10;
            findings.push('UTF-8 karakter kodlaması tanımlanmamış');
        }

       
        const viewportTag = document.querySelector('meta[name="viewport"]');
        if (viewportTag) {
            const content = viewportTag.getAttribute('content');
            if (content.includes('user-scalable=no')) {
                score -= 5;
                findings.push('Viewport ölçeklendirme kısıtlaması erişilebilirliği engelliyor');
            }
        }

   
        const referrerTag = document.querySelector('meta[name="referrer"]');
        if (!referrerTag) {
            score -= 10;
            findings.push('Referrer Policy meta etiketi bulunamadı');
        } else {
            const referrerPolicy = referrerTag.getAttribute('content');
            if (referrerPolicy === 'never' || referrerPolicy === 'always') {
                score -= 5;
                findings.push('Referrer Policy değeri güvenlik açısından optimize edilebilir');
            }
        }

    
        const generatorTag = document.querySelector('meta[name="generator"]');
        if (generatorTag) {
            score -= 5;
            findings.push('Generator meta etiketi sistem bilgisi sızdırıyor');
        }

       
        const robotsTag = document.querySelector('meta[name="robots"]');
        if (!robotsTag) {
            score -= 5;
            findings.push('Robots meta etiketi tanımlanmamış');
        } else {
            const robotsContent = robotsTag.getAttribute('content').toLowerCase();
            if (!robotsContent.includes('noindex,nofollow') && 
                document.location.pathname.includes('/admin')) {
                score -= 15;
                findings.push('Admin sayfası için robots kısıtlaması eksik');
            }
        }

        return {
            score: Math.max(0, score),
            findings
        };
    }

    generateSummaryMessage(score) {
        if (score >= 90) {
            return 'Meta tag güvenliği çok iyi durumda';
        } else if (score >= 70) {
            return 'Meta tag güvenliği kabul edilebilir seviyede, bazı iyileştirmeler yapılabilir';
        } else if (score >= 50) {
            return 'Meta tag güvenliğinde önemli eksiklikler mevcut';
        } else {
            return 'Meta tag güvenliği kritik seviyede düşük';
        }
    }

    checkSEOSecurity(metaTags, seoAnalysis) {
    
        const sitemapTag = document.querySelector('meta[name="sitemap"]');
        if (sitemapTag && !sitemapTag.content.startsWith('https://')) {
            seoAnalysis.score -= 15;
            seoAnalysis.findings.push('Güvensiz sitemap URL\'i');
        }

     
        const robotsTag = document.querySelector('meta[name="robots"]');
        if (robotsTag) {
            const content = robotsTag.content.toLowerCase();
            if (content.includes('index,follow') && 
                (window.location.pathname.includes('/admin') || 
                 window.location.pathname.includes('/dashboard'))) {
                seoAnalysis.score -= 25;
                seoAnalysis.findings.push('Hassas sayfalarda yetersiz robots direktifi');
            }
        }

   
        const descriptionTag = document.querySelector('meta[name="description"]');
        if (descriptionTag) {
            const description = descriptionTag.content;
            if (description.match(/[<>'"]/)) {
                seoAnalysis.score -= 20;
                seoAnalysis.findings.push('Meta description\'da potansiyel XSS riski');
            }
            if (description.match(/\b(admin|password|token)\b/i)) {
                seoAnalysis.score -= 15;
                seoAnalysis.findings.push('Meta description\'da hassas terimler');
            }
        }

        const canonicalTag = document.querySelector('link[rel="canonical"]');
        if (canonicalTag && !canonicalTag.href.startsWith('https://')) {
            seoAnalysis.score -= 10;
            seoAnalysis.findings.push('Güvensiz canonical URL');
        }
    }
}

window.MetaScanner = MetaScanner; 