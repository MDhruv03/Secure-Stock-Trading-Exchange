/**
 * API Service Module for Secure Trading Platform
 * Provides methods to interact with all API endpoints
 */

class ApiClient {
    constructor() {
        this.baseUrl = 'http://127.0.0.1:8000'; // Backend server URL
        this.token = localStorage.getItem('auth_token') || null;
        this.userId = localStorage.getItem('user_id') || null;
    }

    // Set authentication token
    setToken(token, type = 'Bearer') {
        this.token = token;
        this.tokenType = type;
        if (token) {
            localStorage.setItem('auth_token', token);
            localStorage.setItem('token_type', type);
        } else {
            localStorage.removeItem('auth_token');
            localStorage.removeItem('token_type');
        }
    }

    // Set user ID
    setUserId(userId) {
        this.userId = userId;
        if (userId) {
            localStorage.setItem('user_id', userId);
        } else {
            localStorage.removeItem('user_id');
        }
    }

    // Get authorization header
    getAuthHeaders() {
        const headers = {
            'Content-Type': 'application/json',
        };
        if (this.token) {
            headers['Authorization'] = `${localStorage.getItem('token_type') || 'Bearer'} ${this.token}`;
        }
        return headers;
    }

    // Generic request method
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const config = {
            headers: {
                ...this.getAuthHeaders(),
                ...options.headers,
            },
            ...options,
        };

        try {
            const response = await fetch(url, config);
            
            // Handle different response types
            const contentType = response.headers.get('content-type');
            let data;
            
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            } else {
                data = await response.text();
            }

            if (!response.ok) {
                const errorMessage = data.detail || data.message || `HTTP error! status: ${response.status}`;
                if (response.status === 401) {
                    // Clear auth token on unauthorized
                    this.setToken(null);
                    this.setUserId(null);
                }
                throw new Error(errorMessage);
            }

            return data;
        } catch (error) {
            console.error('API request error:', error);
            if (error.message === 'Failed to fetch') {
                throw new Error('Unable to connect to the server. Please check if the server is running.');
            }
            throw error;
        }
    }

    // Authentication methods
    async login(username, password) {
        const data = await this.request('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        
        if (data.success && data.access_token) {
            this.setToken(data.access_token, data.token_type || 'Bearer');
            this.setUserId(data.user_id);
            // Store additional user info
            localStorage.setItem('user_role', data.role || 'trader');
            localStorage.setItem('username', data.username);
        }
        
        return data;
    }

    async register(username, password) {
        const data = await this.request('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        
        return data;
    }

    async logout() {
        const data = await this.request('/api/auth/logout', {
            method: 'POST'
        });
        
        this.setToken(null);
        this.setUserId(null);
        
        return data;
    }

    async changePassword(oldPassword, newPassword) {
        const data = await this.request('/api/auth/change-password', {
            method: 'POST',
            body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
        });
        
        return data;
    }

    // Trading methods
    async createOrder(symbol, side, quantity, price) {
        const data = await this.request('/api/trading/orders', {
            method: 'POST',
            body: JSON.stringify({ symbol, side, quantity, price })
        });
        
        return data;
    }

    async getUserOrders() {
        const data = await this.request('/api/trading/orders');
        return data;
    }

    async getAllOrders() {
        const data = await this.request('/api/trading/orders/all');
        return data;
    }

    async getOrderBook(symbol) {
        const data = await this.request(`/api/trading/orderbook/${symbol}`);
        return data;
    }

    async getVwap(symbol) {
        const data = await this.request(`/api/trading/vwap/${symbol}`);
        return data;
    }

    // Search methods
    async searchTrades(keyword) {
        const data = await this.request('/api/search', {
            method: 'POST',
            body: JSON.stringify({ keyword })
        });
        
        return data;
    }

    // Security methods
    async getSecurityEvents() {
        const data = await this.request('/api/security/events');
        return data;
    }

    async getBlockedIps() {
        const data = await this.request('/api/security/blocked_ips');
        return data;
    }

    async unblockIp(ipAddress) {
        const data = await this.request(`/api/security/unblock_ip/${ipAddress}`, {
            method: 'POST'
        });
        
        return data;
    }

    async getMerkleLeaves() {
        const data = await this.request('/api/security/merkle_leaves');
        return data;
    }

    async getAuditLog(limit = 50) {
        const data = await this.request('/api/security/audit_log');
        return data;
    }

    // Simulation methods
    async simulateSqlInjection() {
        const data = await this.request('/api/security/simulate/sql_injection', {
            method: 'POST'
        });
        
        return data;
    }

    async simulateBruteForce() {
        const data = await this.request('/api/security/simulate/brute_force', {
            method: 'POST'
        });
        
        return data;
    }

    async simulateReplay() {
        const data = await this.request('/api/security/simulate/replay', {
            method: 'POST'
        });
        
        return data;
    }

    async simulateMitm() {
        const data = await this.request('/api/security/simulate/mitm', {
            method: 'POST'
        });
        
        return data;
    }

    // Data methods
    async getLatestOrders(limit = 10) {
        const data = await this.request(`/api/data/orders/latest?limit=${limit}`);
        return data;
    }

    async getMarketOverview() {
        const data = await this.request('/api/data/market/overview');
        return data;
    }

    async getUserPortfolio(userId) {
        // Check if userId is valid before making the API request
        const actualUserId = userId || this.userId;
        if (!actualUserId || actualUserId === 'null') {
            // Return a default response instead of making an API call
            return { portfolio: { total_value: 0, assets: [], transactions: [] } };
        }
        const data = await this.request(`/api/data/portfolio/${actualUserId}`);
        return data;
    }

    async getUserTransactions(userId) {
        const data = await this.request(`/api/data/transactions/${userId || this.userId}`);
        return data;
    }

    // Logs methods
    async getSecurityLogs() {
        const data = await this.request('/api/logs/security');
        return data;
    }

    async getAuditLogs(limit = 50) {
        const data = await this.request(`/api/logs/audit?limit=${limit}`);
        return data;
    }

    async getUserActivityLogs() {
        const data = await this.request('/api/logs/user-activity');
        return data;
    }

    // Attack simulation methods
    async getAttackSimulations() {
        const data = await this.request('/api/attacks/simulations');
        return data;
    }

    // Crypto methods
    async encryptData(data) {
        const result = await this.request('/api/crypto/encrypt', {
            method: 'POST',
            body: JSON.stringify(data)
        });
        
        return result;
    }

    async decryptData(encryptedPackage) {
        const result = await this.request('/api/crypto/decrypt', {
            method: 'POST',
            body: JSON.stringify(encryptedPackage)
        });
        
        return result;
    }

    async signData(data) {
        const result = await this.request('/api/crypto/sign', {
            method: 'POST',
            body: JSON.stringify(data)
        });
        
        return result;
    }

    async verifySignature(data, signature) {
        const result = await this.request('/api/crypto/verify', {
            method: 'POST',
            body: JSON.stringify({ data, signature })
        });
        
        return result;
    }

    async createMerkleRoot(leaves) {
        const result = await this.request('/api/crypto/merkle/generate', {
            method: 'POST',
            body: JSON.stringify({ leaves })
        });
        
        return result;
    }

    async buildMerkleTree(leaves) {
        const result = await this.request('/api/crypto/merkle/build_tree', {
            method: 'POST',
            body: JSON.stringify({ leaves })
        });
        
        return result;
    }

    async generateMerkleProof(leaves, leafIndex) {
        const result = await this.request('/api/crypto/merkle/generate_proof', {
            method: 'POST',
            body: JSON.stringify({ leaves, leaf_index: leafIndex })
        });
        
        return result;
    }

    async verifyMerkleProof(leaf, proof, root) {
        const result = await this.request('/api/crypto/merkle/verify_proof', {
            method: 'POST',
            body: JSON.stringify({ leaf, proof, root })
        });
        
        return result;
    }

    async getMerkleTreeStructure() {
        const result = await this.request('/api/crypto/merkle/tree_structure', {
            method: 'GET'
        });
        
        return result;
    }

    async verifyMerkleTreeIntegrity() {
        const result = await this.request('/api/crypto/merkle/verify_integrity', {
            method: 'GET'
        });
        
        return result;
    }

    async hmacSign(data) {
        const result = await this.request('/api/crypto/hmac/sign', {
            method: 'POST',
            body: JSON.stringify(data)
        });
        
        return result;
    }

    async hmacVerify(data, hmacSignature) {
        const result = await this.request('/api/crypto/hmac/verify', {
            method: 'POST',
            body: JSON.stringify({ data, hmac_signature: hmacSignature })
        });
        
        return result;
    }

    // Health check
    async healthCheck() {
        const data = await this.request('/api/health');
        return data;
    }
}

// Create a singleton instance
export const apiClient = new ApiClient();
export default ApiClient;