class GroqAIClient {
    constructor() {
        this.loadApiKey();
        this.baseURL = 'https://api.groq.com/openai/v1';
        this.model = 'mixtral-8x7b-32768';
        this.requestQueue = [];
        this.isProcessing = false;
        this.lastRequestTime = 0;
        this.minRequestInterval = 5000; 
        this.maxRetries = 3; 
    }

    async loadApiKey() {
        try {
            const result = await chrome.storage.local.get(['groqApiKey']);
            this.apiKey = result.groqApiKey;
        } catch (error) {
            console.error('API key yüklenemedi:', error);
        }
    }

    async getSecurityAdvice(prompt, url, scanType, isButtonClick = false) {
       
        if (!isButtonClick) {
            console.log('Buton tıklanmadı, AI tavsiyesi istenmedi');
            return null;
        }

    
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;
        if (timeSinceLastRequest < this.minRequestInterval) {
            const waitTime = this.minRequestInterval - timeSinceLastRequest;
            await new Promise(resolve => setTimeout(resolve, waitTime));
        }

        return new Promise((resolve, reject) => {
           
            const isDuplicate = this.requestQueue.some(
                req => req.url === url && req.scanType === scanType
            );
            
            if (isDuplicate) {
                console.log(`Duplicate request for ${scanType} on ${url}, skipping`);
                resolve(null);
                return;
            }

            this.requestQueue.push({ 
                prompt,
                url,
                scanType,
                resolve: async (response) => {
                    try {
                        if (!response) {
                            resolve(null);
                            return;
                        }
                        const formattedResponse = {
                            choices: [{
                                message: {
                                    content: response
                                }
                            }]
                        };
                        resolve(formattedResponse);
                    } catch (error) {
                        console.error('AI yanıtı formatlanırken hata:', error);
                        resolve(null);
                    }
                }, 
                reject: (error) => {
                    console.error('AI isteği başarısız:', error);
                    resolve(null);
                },
                retryCount: 0 
            });
            this.processQueue();
        });
    }

    async processQueue() {
        if (this.isProcessing || this.requestQueue.length === 0) return;

        this.isProcessing = true;
        const request = this.requestQueue.shift();

        try {
            const response = await fetch(`${this.baseURL}/chat/completions`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: this.model,
                    messages: [
                        {
                            role: 'system',
                            content: `Sen bir URL güvenlik analizi uzmanısın. SADECE verilen analiz bulgularına göre tavsiye vermelisin.

KURALLAR:
1. Her bulgu için SADECE BİR tavsiye ver
2. Bulunmayan sorunlar hakkında yorum yapma
3. Her tavsiye için bu formatı kullan:
[SEVİYE] Problem: <analiz bulgusunda belirtilen sorun> | Çözüm: <kısa ve net çözüm önerisi>

ÖRNEK:
Bulgu: "URL'de SQL injection açığı var"
Doğru yanıt: "[YÜKSEK] Problem: URL'de SQL injection açığı var | Çözüm: URL parametrelerini SQL injection'a karşı filtreleyin"
Yanlış yanıt: Bulunmayan sorunlar hakkında yorum yapmak veya gereksiz detaylar vermek`
                        },
                        {
                            role: 'user',
                            content: request.prompt
                        }
                    ],
                    temperature: 0.1,
                    max_tokens: 1000
                })
            });

            if (!response.ok) {
                if (response.status === 429 && request.retryCount < this.maxRetries) {
                    request.retryCount++;
                    this.requestQueue.push(request);
                    await new Promise(resolve => 
                        setTimeout(resolve, this.minRequestInterval * (request.retryCount + 1))
                    );
                } else {
                    throw new Error(response.status === 429 ? 
                        'Çok fazla istek yapıldı. Lütfen daha sonra tekrar deneyin.' : 
                        'API yanıt vermedi: ' + response.status
                    );
                }
            } else {
                const data = await response.json();
                if (!data.choices?.[0]?.message?.content) {
                    throw new Error('Geçersiz API yanıtı');
                }
                this.lastRequestTime = Date.now();
                request.resolve(data.choices[0].message.content);
            }

        } catch (error) {
            console.error('Groq API hatası:', error);
            request.reject(error);
        } finally {
            this.isProcessing = false;
            if (this.requestQueue.length > 0) {
               
                const timeSinceLastRequest = Date.now() - this.lastRequestTime;
                const waitTime = Math.max(0, this.minRequestInterval - timeSinceLastRequest);
                setTimeout(() => {
                    this.processQueue();
                }, waitTime);
            }
        }
    }

 
    getQueueLength() {
        return this.requestQueue.length;
    }


    isRateLimited() {
        return Date.now() - this.lastRequestTime < this.minRequestInterval;
    }

    createErrorResponse(message) {
        return {
            error: true,
            message: `AI tavsiyesi alınamadı: ${message}`,
            recommendations: [{
                priority: 'BİLGİ',
                advice: 'Şu anda AI tavsiyeleri kullanılamıyor. Lütfen manuel olarak güvenlik kontrolü yapın.'
            }]
        };
    }

    formatAdvice(content) {
        const recommendations = content.split('\n')
            .filter(line => line.trim())
            .map(line => {
                const priority = line.match(/\[(.*?)\]/)?.[1] || 'BİLGİ';
                const advice = line.replace(/\[.*?\]\s*-?\s*/, '').trim();
                return { priority, advice };
            });

        return {
            error: false,
            message: 'AI tavsiyeleri başarıyla alındı',
            recommendations
        };
    }

    getMetaSecurityPrompt(analysis) {
        return `
            Sadece Meta tag güvenlik analizi sonuçlarına göre tavsiyelerde bulun:
            Skor: ${analysis?.score || 'N/A'}
            Bulgular: ${analysis?.findings?.join('\n') || 'Analiz devam ediyor...'}
            Lütfen sadece yukarıdaki bulgulara göre tavsiye ver. Varsayılan veya genel tavsiyeler verme
        `;
    }

    getHeaderSecurityPrompt(analysis) {
        return `
            Sadece HTTP başlık güvenlik analizi sonuçlarına göre tavsiyelerde bulun:
            Skor: ${analysis?.score || 'N/A'}
            Bulgular: ${analysis?.findings?.join('\n') || 'Analiz devam ediyor...'}
            Lütfen sadece yukarıdaki bulgulara göre tavsiye ver. Varsayılan veya genel tavsiyeler verme
        `;
    }

    getFormSecurityPrompt(analysis) {
        return `
            Sadece Form güvenlik analizi sonuçlarına göre tavsiyelerde bulun:
            Skor: ${analysis.score}
            Bulgular: ${analysis.findings.join('\n')}
            Lütfen sadece yukarıdaki bulgulara göre tavsiye ver. Varsayılan veya genel tavsiyeler verme
        `;
    }

    getContentSecurityPrompt(analysis) {
        return `
            Sadece İçerik güvenlik analizi sonuçlarına göre tavsiyelerde bulun:
            Skor: ${analysis.score}
            Bulgular: ${analysis.findings.join('\n')}
            Lütfen sadece yukarıdaki bulgulara göre tavsiye ver. Varsayılan veya genel tavsiyeler verme
        `;
    }

    getCookieSecurityPrompt(analysis) {
        return `
            Sadece aşağıdaki çerez güvenlik analizi sonuçlarına göre Türkçe tavsiyelerde bulun:
            Skor: ${analysis.score}
            Bulgular: ${analysis.findings.join('\n')}
            
            Lütfen sadece yukarıdaki bulgulara göre tavsiye ver. Varsayılan veya genel tavsiyeler verme.
        `;
    }

    generatePrompt(scanType, analysisData) {
        if (!analysisData || typeof analysisData !== 'object') {
            return 'Analiz verisi bulunamadı';
        }

        try {
            const basePrompt = `
                Aşağıdaki güvenlik analizi sonuçlarına göre tavsiyeler ver:
                Skor: ${analysisData.score}
                Tespit edilen sorunlar:
                ${analysisData.findings.map(f => `- ${f}`).join('\n')}

                SADECE yukarıdaki sorunlar için tavsiye ver.
                Her sorun için [SEVİYE] Problem: <sorun> | Çözüm: <çözüm> formatını kullan.
                Genel tavsiyeler verme, sadece bulunan sorunlara odaklan.
                Verdiğin çözümler metin olarak verilsin bash in icinde verme !!!
            `;

            const scannerPrompts = {
                url: `URL GÜVENLİK ANALİZİ:\n${basePrompt}`,
                meta: `META TAG ANALİZİ:\n${basePrompt}`,
                form: `FORM GÜVENLİK ANALİZİ:\n${basePrompt}`,
                header: `HTTP HEADER ANALİZİ:\n${basePrompt}`,
                content: `İÇERİK GÜVENLİK ANALİZİ:\n${basePrompt}`,
                cookie: `ÇEREZ GÜVENLİK ANALİZİ:\n${basePrompt}`
            };

            return scannerPrompts[scanType] || 'Analiz tipi için prompt bulunamadı';
        } catch (error) {
            console.error('Prompt oluşturma hatası:', error);
            return 'Güvenlik analizi yapılıyor...';
        }
    }

    async saveApiKey(apiKey) {
        try {
            await chrome.storage.local.set({ groqApiKey: apiKey });
            this.apiKey = apiKey;
            return true;
        } catch (error) {
            console.error('API key kaydetme hatası:', error);
            return false;
        }
    }

    async testApiKey() {
        try {
            const response = await fetch(`${this.baseURL}/chat/completions`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: this.model,
                    messages: [
                        { role: 'user', content: 'Test message' }
                    ],
                    max_tokens: 1
                })
            });

            const data = await response.json();
            return { success: !data.error };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
}

window.GroqAIClient = GroqAIClient; 