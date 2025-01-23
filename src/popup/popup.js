
(async () => {
    document.addEventListener('DOMContentLoaded', async () => {
        try {
            const dashboard = new SecurityDashboard();
            
        
            const result = await chrome.storage.local.get(['groqApiKey']);
            if (result.groqApiKey) {
                document.getElementById('apiKeyModal').style.display = 'none';
                document.getElementById('mainContent').style.display = 'block';
                
           
                await dashboard.loadLastScan();
            } else {
                document.getElementById('apiKeyModal').style.display = 'block';
                document.getElementById('mainContent').style.display = 'none';
            }
        } catch (error) {
            console.error('Başlatma hatası:', error);
        }
    });
})();


const apiKeyForm = document.getElementById('apiKeyForm');
apiKeyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const apiKey = document.getElementById('apiKey').value.trim();
    const errorElement = document.getElementById('apiKeyError');

    try {
      
        if (!apiKey.startsWith('gsk_')) {
            throw new Error('API anahtarı "gsk_" ile başlamalıdır');
        }

 
        const testResult = await testApiKey(apiKey);
        if (testResult.success) {
         
            await chrome.storage.local.set({ groqApiKey: apiKey });
            
         
            document.getElementById('apiKeyModal').style.display = 'none';
            document.getElementById('mainContent').style.display = 'block';
            initializeDashboard();
        } else {
            throw new Error('API anahtarı geçersiz');
        }
    } catch (error) {
        errorElement.textContent = error.message;
        errorElement.style.display = 'block';
        document.getElementById('apiKey').classList.add('error');
    }
});


async function testApiKey(apiKey) {
    try {
        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'mixtral-8x7b-32768',
                messages: [
                    { 
                        role: 'system', 
                        content: 'You are a helpful assistant.' 
                    },
                    { 
                        role: 'user', 
                        content: 'Test message' 
                    }
                ],
                temperature: 0.3,
                max_tokens: 1
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error?.message || 'API yanıt vermedi');
        }

        const data = await response.json();
        return { success: true, data };
    } catch (error) {
        console.error('API test hatası:', error);
        return { 
            success: false, 
            error: error.message || 'API bağlantısı başarısız'
        };
    }
}


function initializeDashboard() {
    const dashboard = new SecurityDashboard();
    dashboard.startAnalysis();
}

function showApiKeyModal() {
    document.getElementById('apiKeyModal').style.display = 'block';
    document.getElementById('mainContent').style.display = 'none';
}

function hideApiKeyModal() {
    document.getElementById('apiKeyModal').style.display = 'none';
    document.getElementById('mainContent').style.display = 'block';
}

function showMainContent() {
    document.getElementById('apiKeyModal').style.display = 'none';
    document.getElementById('mainContent').style.display = 'block';
   
    startAnalysis();
}


chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'NEED_API_KEY') {
        document.getElementById('apiKeyModal').style.display = 'block';
    }
});

class SecurityDashboard {
    constructor() {
        this.groqClient = new window.GroqAIClient();
        this.scanners = {
            url: new window.PassiveAnalyzer(),
            form: new window.FormScanner(),
            header: new window.HeaderScanner(),
            meta: new window.MetaScanner(),
            content: new window.ContentScanner(),
            cookie: new window.CookieScanner()
        };
        this.lastResults = null;
        this.currentUrl = null;
        this.scanStatus = {
            total: 6,
            completed: 0,
            startTime: 0
        };
        this.initializeEventListeners();
        this.initializeUI();
    }

    initializeUI() {
   
        const mainScoreCircle = document.querySelector('.score-circle');
        mainScoreCircle.style.setProperty('--score', '0deg');
        mainScoreCircle.querySelector('span').textContent = '?';

 
        document.querySelectorAll('.section-score').forEach(score => {
            score.textContent = '?';
            score.style.backgroundColor = '#444';
        });

 
        document.querySelectorAll('.findings-list').forEach(list => {
            list.innerHTML = '<li class="finding-item waiting">Analiz için butona tıklayın...</li>';
        });

      
        document.getElementById('aiRecommendations').innerHTML = 
            '<div class="ai-recommendation waiting">Analiz için butona tıklayın...</div>';
    }

    initializeEventListeners() {
     
        const scanButton = document.getElementById('startScan');
        if (scanButton) {
          
            scanButton.replaceWith(scanButton.cloneNode(true));
            
            
            document.getElementById('startScan').addEventListener('click', () => {
                console.log('Tarama başlatılıyor...'); 
                this.startAnalysis();
            });
        }

      
        document.getElementById('showLegal').addEventListener('click', () => {
            document.getElementById('legalModal').style.display = 'block';
        });

        document.querySelector('.close-button').addEventListener('click', () => {
            document.getElementById('legalModal').style.display = 'none';
        });

       
        const tabButtons = document.querySelectorAll('.tab-button');
        tabButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const tabId = e.target.dataset.tab;
                this.switchTab(tabId);
            });
        });
    }

    switchTab(tabId) {
   
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabId);
        });


        document.querySelectorAll('.tab-pane').forEach(pane => {
            pane.classList.toggle('active', pane.id === `${tabId}Tab`);
            if (pane.id === `${tabId}Tab`) {
                
                pane.scrollTop = 0;
            }
        });
    }

    async startAnalysis() {
        const button = document.getElementById('startScan');
        if (!button) return;

        try {
            button.disabled = true;
            button.textContent = 'Analiz başlatılıyor...';
            
       
            this.initializeUI();
            
            const [tab] = await chrome.tabs.query({ 
                active: true, 
                currentWindow: true,
                url: ['http://*/*', 'https://*/*']
            });

            if (!tab) {
                throw new Error('Analiz edilebilir bir sayfa bulunamadı');
            }

          
            this.currentUrl = tab.url;
            const results = await this.runAllScans(tab);
            this.lastResults = results;
            
           
            await this.updateDashboard(results);

        } catch (error) {
            console.error('Analiz hatası:', error);
            this.showError(error.message);
        } finally {
            if (button) {
                button.disabled = false;
                button.textContent = 'Yeni Tarama Başlat';
            }
        }
    }

    async loadLastScan() {
        try {
          
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            const url = tab.url;
            const result = await chrome.storage.local.get([`lastScan_${url}`]);
            const lastScan = result[`lastScan_${url}`];

            if (lastScan && lastScan.results) {
             
                this.updateScores(lastScan.results);
                this.updateFindings(lastScan.results);
                
             
                const container = document.getElementById('aiRecommendations');
                if (lastScan.aiRecommendations) {
                    container.innerHTML = lastScan.aiRecommendations;
                } else {
                    container.innerHTML = '<div class="ai-recommendation waiting">Analiz için butona tıklayın...</div>';
                }
            } else {
               
                this.initializeUI();
            }
        } catch (error) {
            console.error('Son tarama yüklenirken hata:', error);
            this.initializeUI();
        }
    }

    async saveScanResults(results, aiRecommendationsHtml) {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            const url = tab.url;
            await chrome.storage.local.set({
                [`lastScan_${url}`]: {
                    results,
                    aiRecommendations: aiRecommendationsHtml,
                    timestamp: Date.now()
                }
            });
        } catch (error) {
            console.error('Tarama sonuçları kaydedilemedi:', error);
        }
    }

    async updateAIRecommendationsGradually(results) {
        const container = document.getElementById('aiRecommendations');
        container.innerHTML = '<h4>🔍 Güvenlik Tavsiyeleri Hazırlanıyor...</h4>';

        try {
            const [tab] = await chrome.tabs.query({ 
                active: true, 
                currentWindow: true 
            });
            const url = tab.url;

        
            const scannerTypes = ['url', 'form', 'header', 'meta', 'content', 'cookie'];
            let hasAnyResponse = false;
            
           
            const minRequestInterval = 5000; 
            let lastRequestTime = 0;

            for (const type of scannerTypes) {
                const result = results[type];
                if (!result) continue;

                try {
                 
                    const now = Date.now();
                    const timeSinceLastRequest = now - lastRequestTime;
                    if (timeSinceLastRequest < minRequestInterval) {
                        const waitTime = minRequestInterval - timeSinceLastRequest;
                        await new Promise(resolve => setTimeout(resolve, waitTime));
                    }

                    const loadingDiv = document.createElement('div');
                    loadingDiv.className = 'ai-loading';
                    loadingDiv.innerHTML = `
                        <i class="fas fa-spinner fa-spin"></i>
                        ${type.toUpperCase()} için tavsiyeler alınıyor...
                        <small>(${scannerTypes.indexOf(type) + 1}/${scannerTypes.length})</small>
                    `;
                    container.appendChild(loadingDiv);
                    
                   
                    const prompt = this.groqClient.generatePrompt(type, result);
                    lastRequestTime = Date.now();
                    const aiResponse = await this.groqClient.getSecurityAdvice(prompt, url, type, true);

                   
                    loadingDiv.remove();
                    
               
                    if (aiResponse && aiResponse.choices?.[0]?.message?.content) {
                        hasAnyResponse = true;
                        const section = document.createElement('div');
                        section.className = 'ai-section';
                        section.innerHTML = `
                            <h5>${type.toUpperCase()} Tavsiyeleri:</h5>
                            ${this.formatAIResponse(aiResponse)}
                        `;
                        container.appendChild(section);
                    }
                } catch (error) {
                    console.error(`${type} tavsiyeleri alınırken hata:`, error);
                    loadingDiv?.remove();
                }
            }

            if (hasAnyResponse) {
                const summaryDiv = document.createElement('div');
                summaryDiv.className = 'ai-summary';
                summaryDiv.innerHTML = `
                    <h5>📊 Güvenlik Analizi Özeti</h5>
                    <div class="summary-content">
                        Toplam ${scannerTypes.length} kategori analiz edildi.
                        Ortalama güvenlik skoru: ${this.calculateOverallScore(results)}/100
                    </div>
                `;
                container.appendChild(summaryDiv);

           
                await this.saveScanResults(results, container.innerHTML);
            } else {
                container.innerHTML = `
                    <div class="ai-error">
                        <i class="fas fa-exclamation-circle"></i>
                        AI tavsiyeleri alınamadı. Lütfen internet bağlantınızı kontrol edip tekrar deneyin.
                    </div>
                `;
            }
        } catch (error) {
            console.error('AI tavsiyeleri güncellenirken hata:', error);
            container.innerHTML = `
                <div class="ai-error">
                    <i class="fas fa-exclamation-circle"></i>
                    AI tavsiyeleri alınamadı. Lütfen internet bağlantınızı kontrol edip tekrar deneyin.
                </div>
            `;
        }
    }

    async runAllScans(tab) {
        try {
           
            const scanOrder = [
                {
                    name: 'url',
                    message: 'URL güvenliği kontrol ediliyor...',
                    func: () => this.scanners.url.analyzeURL(tab)
                },
                {
                    name: 'form',
                    message: 'Form güvenliği analiz ediliyor...',
                    func: () => this.scanners.form.analyzeForms(tab)
                },
                {
                    name: 'header',
                    message: 'HTTP başlıkları kontrol ediliyor...',
                    func: () => this.scanners.header.analyzeHeaders(tab)
                },
                {
                    name: 'meta',
                    message: 'Meta etiketleri analiz ediliyor...',
                    func: () => this.scanners.meta.analyzeMetaTags(tab)
                },
                {
                    name: 'content',
                    message: 'İçerik güvenliği kontrol ediliyor...',
                    func: () => this.scanners.content.analyzeContent(tab)
                },
                {
                    name: 'cookie',
                    message: 'Çerez güvenliği analiz ediliyor...',
                    func: () => this.scanners.cookie.analyzeCookies(tab)
                }
            ];

            const results = {};
            
          
            for (const scan of scanOrder) {
                try {
                    results[scan.name] = await this.runScan(scan.message, scan.func);
                } catch (error) {
                    console.error(`${scan.name} analizi hatası:`, error);
                    results[scan.name] = {
                        error: true,
                        score: 0,
                        message: `${scan.name} analizi başarısız: ${error.message}`,
                        findings: [`${scan.name} analizi yapılamadı: ${error.message}`]
                    };
                }
            }

            return results;
        } catch (error) {
            console.error('Scan error:', error);
            return {};
        }
    }

    async runScan(statusMessage, scanFunction) {
        this.updateAnalysisStatus(statusMessage);
        try {
            const result = await scanFunction();
            this.scanStatus.completed++;
            const progress = Math.round((this.scanStatus.completed / this.scanStatus.total) * 100);
            const duration = ((Date.now() - this.scanStatus.startTime) / 1000).toFixed(1);
            
    
            this.updateAnalysisStatus(`${statusMessage.replace('...', '')} tamamlandı (${progress}%, ${duration}s)`);
            

            await new Promise(resolve => setTimeout(resolve, 500));
            
            return result;
        } catch (error) {
            console.error('Scan error:', error);
            this.updateAnalysisStatus(`${statusMessage.replace('...', '')} başarısız`);
            throw error;
        }
    }

    updateAnalysisStatus(message) {
        const button = document.getElementById('startScan');
        button.textContent = message;
        

        const progress = Math.round((this.scanStatus.completed / this.scanStatus.total) * 100);
        button.style.background = `linear-gradient(to right, #4CAF50 ${progress}%, #666 ${progress}%)`;
    }

    async updateDashboard(results) {
        try {
        
            this.updateScores(results);
            
      
            this.updateFindings(results);
            
        
            await this.updateAIRecommendationsGradually(results);
            
        } catch (error) {
            console.error('Dashboard güncelleme hatası:', error);
        }
    }

    updateScores(results) {
      
        const overallScore = this.calculateOverallScore(results);
        this.updateOverallScore(overallScore);

  
        this.updateSection('urlFindings', results.url);
        this.updateSection('formFindings', results.form);
        this.updateSection('headerFindings', results.header);
        this.updateSection('metaFindings', results.meta);
        this.updateSection('contentFindings', results.content);
        this.updateSection('cookieFindings', results.cookie);
    }

    calculateOverallScore(results) {
        const scores = Object.values(results).map(r => r.score || 0);
        return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    }

    updateOverallScore(score) {
        const scoreCircle = document.querySelector('.score-circle');
        const scoreSpan = scoreCircle.querySelector('span');
        
        scoreCircle.style.setProperty('--score', `${score * 3.6}deg`);
        scoreSpan.textContent = score;

       
        const color = score >= 80 ? '#4CAF50' : score >= 60 ? '#FFEB3B' : '#FF5252';
        scoreCircle.style.background = `conic-gradient(${color} ${score * 3.6}deg, #333 0deg)`;
    }

    updateSection(sectionId, results) {
        const section = document.getElementById(sectionId);
        if (!section) return;

        section.innerHTML = ''; 
        
        results.findings.forEach(finding => {
            const li = document.createElement('li');
            li.className = `finding-item ${this.getSeverityClass(finding)}`;
            li.textContent = finding;
            section.appendChild(li);
        });

   
        const scoreElement = section.closest('.scan-section').querySelector('.section-score');
        if (scoreElement) {
            scoreElement.textContent = results.score;
            scoreElement.style.backgroundColor = this.getScoreColor(results.score);
        }
    }

    createRecommendationElement(finding, scanType) {
        const div = document.createElement('div');
        div.className = 'security-recommendation';

        const severity = this.determineSeverity(finding);
        const solution = this.getSolutionForFinding(finding, scanType);

        div.innerHTML = `
            <div class="recommendation-header ${severity}">
                <span class="severity-badge">${this.getSeverityText(severity)}</span>
                <span class="finding-text">${finding}</span>
            </div>
            <div class="recommendation-body">
                <h5>🛠️ Çözüm Önerisi:</h5>
                <p>${solution}</p>
                ${this.getAdditionalResources(scanType, finding)}
            </div>
        `;

        return div;
    }

    getSolutionForFinding(finding, scanType) {
        const solutions = {
            url: {
                'HTTP kullanılıyor': 'Web sitenizi HTTPS protokolüne geçirin. SSL sertifikası için Let\'s Encrypt gibi ücretsiz servisleri kullanabilirsiniz.',
                'Güvensiz bağlantı': 'Sitenizin SSL sertifikasını güncelleyin ve HSTS politikası uygulayın.',
                'HSTS eksik': 'Web sunucunuza Strict-Transport-Security header\'ı ekleyin.'
            },
            form: {
                'CSRF token': 'Form işlemlerinize CSRF token koruması ekleyin. Sunucu tarafında token doğrulaması yapın.',
                'Input validasyonu': 'Tüm form alanlarına uygun validasyon kuralları ekleyin. Hem client hem server tarafında kontrol yapın.'
            },
            header: {
                'CSP eksik': 'Content-Security-Policy header\'ı ekleyerek güvenli kaynak politikası belirleyin.',
                'X-Frame-Options': 'Clickjacking saldırılarına karşı X-Frame-Options: DENY veya SAMEORIGIN kullanın.'
            },
            meta: {
                'Charset eksik': 'Meta charset tanımı ekleyerek karakter kodlamasını belirtin: <meta charset="UTF-8">',
                'X-UA-Compatible': 'IE uyumluluğu için X-UA-Compatible meta tag ekleyin.',
                'Viewport eksik': 'Mobil uyumluluk için viewport meta tag ekleyin.',
                'Description eksik': 'SEO için description meta tag ekleyin.',
                'Robots eksik': 'Arama motoru indekslemesi için robots meta tag ekleyin.'
            },
            content: {
                'Güvensiz script': 'Inline script kullanımından kaçının, harici script dosyaları kullanın.',
                'Eski jQuery': 'jQuery kütüphanesini güncel sürüme yükseltin.',
                'Mixed content': 'Tüm kaynakları HTTPS üzerinden yükleyin.',
                'Eval kullanımı': 'Eval() kullanımından kaçının, güvenli alternatifler kullanın.',
                'innerHTML': 'innerHTML yerine textContent veya innerText kullanın.'
            },
            cookie: {
                'Secure flag': 'Çerezlerinize Secure flag ekleyerek sadece HTTPS üzerinden iletilmelerini sağlayın.',
                'HttpOnly': 'Hassas çerezlere HttpOnly flag ekleyerek XSS saldırılarından koruyun.',
                'SameSite': 'CSRF koruması için SameSite=Strict veya Lax kullanın.',
                'Expires': 'Çerezler için uygun son kullanma tarihi belirleyin.',
                'Path': 'Çerezlerin erişim kapsamını Path attribute ile sınırlayın.'
            }
        };

     
        let solution = 'Bu güvenlik açığını gidermek için sistem yöneticinize başvurun.';

    
        Object.entries(solutions[scanType] || {}).forEach(([key, value]) => {
            if (finding.toLowerCase().includes(key.toLowerCase())) {
                solution = value;
            }
        });

        return solution;
    }

    getAdditionalResources(scanType, finding) {
        const resources = {
            url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security',
            form: 'https://owasp.org/www-community/attacks/csrf',
            header: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
            meta: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta',
            content: 'https://developer.mozilla.org/en-US/docs/Web/Security/Types_of_attacks',
            cookie: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies'
        };

        return `
            <div class="additional-resources">
                <h5>📚 Faydalı Kaynaklar:</h5>
                <a href="${resources[scanType]}" target="_blank" rel="noopener noreferrer">
                    Detaylı bilgi için tıklayın
                </a>
            </div>
        `;
    }

    getSeverityText(severity) {
        const texts = {
            critical: '🚨 Kritik Risk',
            warning: '⚠️ Orta Risk',
            info: 'ℹ️ Düşük Risk'
        };
        return texts[severity] || texts.info;
    }

    showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.style.display = 'block';
        errorDiv.textContent = message;
        
        const container = document.querySelector('.main-container');
        container.insertBefore(errorDiv, container.firstChild);
        
        setTimeout(() => errorDiv.remove(), 5000);
    }

    determineSeverity(finding) {
        const lowerFinding = finding.toLowerCase();
        
       
        if (lowerFinding.includes('kritik') || 
            lowerFinding.includes('yüksek risk') ||
            lowerFinding.includes('güvensiz') ||
            lowerFinding.includes('tehlikeli') ||
            lowerFinding.includes('csrf') ||
            lowerFinding.includes('xss') ||
            lowerFinding.includes('injection')) {
            return 'critical';
        }
   
        if (lowerFinding.includes('uyarı') || 
            lowerFinding.includes('orta') ||
            lowerFinding.includes('eksik') ||
            lowerFinding.includes('önerilir') ||
            lowerFinding.includes('iyileştirme')) {
            return 'warning';
        }
        
     
        return 'info';
    }

    getSeverityClass(finding) {
        return this.determineSeverity(finding);
    }

    getScoreColor(score) {
        if (score >= 80) {
            return '#4CAF50'; 
        } else if (score >= 60) {
            return '#FFC107'; 
        } else if (score >= 40) {
            return '#FF9800'; 
        } else {
            return '#F44336'; 
        }
    }

    generateSecurityPrompt(results) {
       
        const prompts = {
            url: this.generateURLPrompt(results.url),
            form: this.generateFormPrompt(results.form),
            header: this.generateHeaderPrompt(results.header),
            meta: this.generateMetaPrompt(results.meta),
            content: this.generateContentPrompt(results.content),
            cookie: this.generateCookiePrompt(results.cookie)
        };

       
        const criticalScanners = Object.entries(results)
            .sort((a, b) => a[1].score - b[1].score)
            .slice(0, 3);

       
        const prompt = `
            Sadece aşağıdaki güvenlik analiz sonuçlarına göre, kullanıcı dostu tavsiyeler ver:

            ${criticalScanners.map(([type, result]) => prompts[type]).join('\n\n')}

            Lütfen tavsiyeleri şu formatta ver:
            [ÖNCELİK SEVİYESİ] Problem: ... | Çözüm: ...

            Önemli: 
            - Her tavsiye teknik olmayan kullanıcılar için anlaşılır olmalı
            - Somut çözüm adımları içermeli
            - Öncelik seviyeleri: YÜKSEK, ORTA veya DÜŞÜK olmalı
            - Sadece yukarıdaki bulgulara göre tavsiye ver
            - Genel veya varsayılan tavsiyeler verme
        `;

        return prompt;
    }

    generateURLPrompt(result) {
        return `
        URL GÜVENLİK ANALİZİ:
        Skor: ${result.score}
        Bulgular:
        ${result.findings.map(f => `- ${f}`).join('\n')}
        
        Lütfen sadece yukarıdaki bulgulara göre tavsiye ver. Varsayılan veya genel tavsiyeler verme.
        `;
    }

    generateFormPrompt(result) {
        return `
        FORM GÜVENLİK ANALİZİ:
        Skor: ${result.score}
        Bulgular:
        ${result.findings.map(f => `- ${f}`).join('\n')}
        
        Lütfen sadece yukarıdaki bulgulara göre tavsiye ver. Varsayılan veya genel tavsiyeler verme.
        `;
    }

    generateHeaderPrompt(result) {
        if (!result || !result.findings) {
            return 'Header güvenlik analizi yapılamadı.';
        }

        return `
        HTTP HEADER GÜVENLİK ANALİZİ:
        Skor: ${result.score}
        Bulgular:
        ${result.findings.map(f => `- ${f}`).join('\n')}
        
        Lütfen sadece yukarıdaki bulgulara göre tavsiye ver. Varsayılan veya genel tavsiyeler verme.
        `;
    }

    generateMetaPrompt(result) {
        return `
        META TAG ANALİZİ:
        Skor: ${result.score}
        Bulgular:
        ${result.findings.map(f => `- ${f}`).join('\n')}
        
        Lütfen sadece yukarıdaki bulgulara göre tavsiye ver. Varsayılan veya genel tavsiyeler verme.
        `;
    }

    generateContentPrompt(result) {
        return `
        İÇERİK GÜVENLİK ANALİZİ:
        Skor: ${result.score}
        Bulgular:
        ${result.findings.map(f => `- ${f}`).join('\n')}
        
        Lütfen sadece yukarıdaki bulgulara göre tavsiye ver. Varsayılan veya genel tavsiyeler verme.
        `;
    }

    generateCookiePrompt(result) {
        return `
        ÇEREZ GÜVENLİK ANALİZİ:
        Skor: ${result.score}
        Bulgular:
        ${result.findings.map(f => `- ${f}`).join('\n')}
        
        Lütfen sadece yukarıdaki bulgulara göre tavsiye ver. Varsayılan veya genel tavsiyeler verme.
        `;
    }

    formatAIResponse(response) {
        try {
        
            if (typeof response === 'string') {
                return response;
            }

          
            if (!response || !response.choices || !response.choices[0] || !response.choices[0].message) {
                throw new Error('Geçersiz AI yanıtı formatı');
            }

            
            const message = response.choices[0].message.content;
            
       
            return message.split('\n')
                .filter(line => line.trim()) 
                .map(line => {
                   
                    let priorityClass = 'priority-medium';
                    if (line.includes('[YÜKSEK]')) priorityClass = 'priority-high';
                    if (line.includes('[DÜŞÜK]')) priorityClass = 'priority-low';

                    
                    const [problem, solution] = line.split('|').map(s => s?.trim() || '');

                    return `
                        <div class="ai-recommendation ${priorityClass}">
                            <div class="recommendation-header">
                                ${problem}
                            </div>
                            ${solution ? `
                                <div class="recommendation-body">
                                    ${solution}
                                </div>
                            ` : ''}
                        </div>
                    `;
                })
                .join('') || 'Tavsiye bulunamadı';

        } catch (error) {
            console.error('AI yanıtı formatlanırken hata:', error);
            return `
                <div class="ai-recommendation priority-medium">
                    <div class="recommendation-header">
                        AI tavsiyesi şu anda kullanılamıyor
                    </div>
                    <div class="recommendation-body">
                        Lütfen daha sonra tekrar deneyin.
                    </div>
                </div>
            `;
        }
    }

    updateFindings(results) {
        Object.entries(results).forEach(([scanType, result]) => {
            const sectionId = `${scanType}Findings`;
            const section = document.getElementById(sectionId);
            if (!section) return;

            
            section.innerHTML = '';

     
            if (result.findings && result.findings.length > 0) {
                result.findings.forEach(finding => {
                    const li = document.createElement('li');
                    li.className = `finding-item ${this.getSeverityClass(finding)}`;
                    li.textContent = finding;
                    section.appendChild(li);
                });
            } else {
                const li = document.createElement('li');
                li.className = 'finding-item info';
                li.textContent = 'Bu kategoride sorun tespit edilmedi';
                section.appendChild(li);
            }

          
            const scoreElement = section.closest('.scan-section')?.querySelector('.section-score');
            if (scoreElement) {
                scoreElement.textContent = result.score;
                scoreElement.style.backgroundColor = this.getScoreColor(result.score);
            }
        });
    }

    async getAIRecommendations(results) {
        try {
            const prompt = this.generateSecurityPrompt(results);
            const response = await this.groqClient.getSecurityAdvice(prompt, this.currentUrl, 'recommendations');
            
            if (!response || !response.choices || !response.choices[0] || !response.choices[0].message) {
                throw new Error('Geçersiz AI yanıtı');
            }

            const recommendations = response.choices[0].message.content
                .split('\n')
                .filter(line => line.trim())
                .map(line => {
                    const [priority, ...rest] = line.split(']');
                    const [problem, solution] = rest.join(']').split('|').map(s => s?.trim() || '');
                    
                    return {
                        priority: priority.replace('[', '').trim(),
                        problem: problem,
                        solution: solution
                    };
                });

            return recommendations;
        } catch (error) {
            console.error('AI tavsiyeleri alınamadı:', error);
            return [];
        }
    }

    displayAIRecommendations(recommendations) {
        const container = document.getElementById('aiRecommendations');
        container.innerHTML = '';

        recommendations.forEach(rec => {
            const recommendationElement = this.createRecommendationElement(rec.problem, 'url');
            container.appendChild(recommendationElement);
        });
    }
}
