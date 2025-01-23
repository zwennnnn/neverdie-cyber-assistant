const config = {
    api: {
        groq: {
            baseUrl: 'https://api.groq.com/v1',
            model: 'mixtral-8x7b-32768',
            timeout: 10000
        }
    },
    scanner: {
        timeouts: {
            request: 5000,
            analysis: 30000
        },
        thresholds: {
            critical: 90,
            warning: 70,
            info: 50
        }
    },
    security: {
        headers: {
            required: [
                'content-security-policy',
                'strict-transport-security',
                'x-frame-options',
                'x-content-type-options'
            ],
            recommended: [
                'permissions-policy',
                'referrer-policy',
                'x-xss-protection'
            ]
        },
        cookies: {
            maxAge: 31536000, 
            secureRequired: true,
            sameSiteStrict: true
        }
    },
    ui: {
        refreshInterval: 5000,
        maxRetries: 3,
        animations: true
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = config;
} else {
    window.config = config;
} 