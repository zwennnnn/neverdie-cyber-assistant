class BackgroundService {
    constructor() {
        this.scanResults = new Map();
        this.config = {
            timeouts: {
                request: 5000,
                analysis: 30000
            }
        };
        this.initializeListeners();
    }

    initializeListeners() {
     
        chrome.tabs.onActivated.addListener(async (activeInfo) => {
            await this.handleTabChange(activeInfo.tabId);
        });

       
        chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
            if (changeInfo.status === 'complete') {
                await this.handleTabChange(tabId);
            }
        });

    
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            if (request.type === 'NEED_API_KEY') {
             
                chrome.action.setPopup({ popup: 'src/popup/popup.html' });
                return true;
            }

            if (request.type === 'SCAN_RESULTS_UPDATED') {
                
                if (sender.tab) {
                    this.scanResults.set(sender.tab.id, request.data);
                }
                return true;
            }

            if (request.type === 'GET_SCAN_RESULTS') {
               
                const results = this.scanResults.get(request.tabId);
                sendResponse({ success: true, data: results || null });
                return true;
            }
            return false;
        });
    }

    async handleTabChange(tabId, changeInfo, tab) {
        try {
            
            if (!tab?.url || !changeInfo.status || changeInfo.status !== 'complete') {
                return;
            }

          
            if (tab.url.startsWith('chrome://') || 
                tab.url.startsWith('edge://') || 
                tab.url.startsWith('about:') ||
                tab.url.startsWith('chrome-extension://')) {
                return;
            }

       
            
        } catch (error) {
            console.error('Tab change error:', error);
        }
    }

    async performInitialScan(tab) {
        try {
            const results = await this.runQuickScan(tab);
            this.scanResults.set(tab.id, results);
            
       
            chrome.runtime.sendMessage({
                type: 'SCAN_RESULTS_UPDATED',
                data: results
            }).catch(() => {
              
                console.log('Popup not ready yet');
            });
        } catch (error) {
            console.error('Initial scan error:', error);
        }
    }

    async runQuickScan(tab) {
        return {
            url: await this.checkBasicSecurity(tab.url),
            timestamp: new Date().toISOString()
        };
    }

    async checkBasicSecurity(url) {
        try {
            const urlObj = new URL(url);
            return {
                isHTTPS: urlObj.protocol === 'https:',
                domain: urlObj.hostname,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            return { error: error.message };
        }
    }
}


const backgroundService = new BackgroundService(); 