/**
 * Visualization Module for Secure Trading Platform
 * Handles chart creation, real-time updates, and data visualization
 */

import { domUtils, dateUtils, numberUtils } from './utils.js';

class ChartManager {
    constructor() {
        this.charts = new Map();
        this.dataStreams = new Map();
    }

    // Create a new chart
    createChart(containerId, type = 'line', options = {}) {
        const container = domUtils.getElement(containerId);
        if (!container) {
            console.error(`Container with ID ${containerId} not found`);
            return null;
        }

        // Remove existing canvas if present
        const existingCanvas = container.querySelector('canvas');
        if (existingCanvas) {
            existingCanvas.remove();
        }

        // Create new canvas
        const canvas = document.createElement('canvas');
        container.appendChild(canvas);

        // Create chart instance
        const chart = new Chart(canvas, {
            type: type,
            data: {
                labels: [],
                datasets: []
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        labels: {
                            color: '#e2e8f0'
                        }
                    },
                    tooltip: {
                        backgroundColor: '#1a202c',
                        titleColor: '#00ff88',
                        bodyColor: '#e2e8f0',
                        borderColor: '#2d3748',
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#64748b'
                        },
                        grid: {
                            color: '#2d3748'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#64748b'
                        },
                        grid: {
                            color: '#2d3748'
                        }
                    }
                },
                ...options
            }
        });

        // Store chart reference
        this.charts.set(containerId, chart);
        return chart;
    }

    // Update chart data
    updateChart(containerId, data) {
        const chart = this.charts.get(containerId);
        if (!chart) {
            console.error(`Chart with ID ${containerId} not found`);
            return false;
        }

        chart.data = data;
        chart.update();
        return true;
    }

    // Add data point to chart
    addDataPoint(containerId, datasetIndex, label, data) {
        const chart = this.charts.get(containerId);
        if (!chart) return false;

        chart.data.labels.push(label);
        chart.data.datasets[datasetIndex].data.push(data);
        
        // Keep only the last N points to prevent memory issues
        const maxPoints = 50;
        if (chart.data.labels.length > maxPoints) {
            chart.data.labels.shift();
            chart.data.datasets.forEach(dataset => {
                if (dataset.data.length > maxPoints) {
                    dataset.data.shift();
                }
            });
        }

        chart.update();
        return true;
    }

    // Remove chart
    removeChart(containerId) {
        const chart = this.charts.get(containerId);
        if (chart) {
            chart.destroy();
            this.charts.delete(containerId);
        }
    }

    // Create market price chart
    createMarketPriceChart(containerId, symbol) {
        const chart = this.createChart(containerId, 'line', {
            animation: {
                duration: 300
            },
            scales: {
                x: {
                    display: false // Hide x-axis for real-time updates
                }
            }
        });

        if (chart) {
            chart.data = {
                labels: [],
                datasets: [{
                    label: `${symbol} Price`,
                    data: [],
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            };
            chart.update();
        }

        return chart;
    }

    // Update market price chart with new data
    updateMarketPriceChart(containerId, price) {
        const chart = this.charts.get(containerId);
        if (!chart) return false;

        const now = new Date();
        const timeLabel = `${now.getHours()}:${now.getMinutes()}:${now.getSeconds()}`;

        this.addDataPoint(containerId, 0, timeLabel, price);
        return true;
    }

    // Create portfolio value chart
    createPortfolioChart(containerId) {
        const chart = this.createChart(containerId, 'line', {
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    labels: {
                        color: '#e2e8f0',
                        usePointStyle: true
                    }
                }
            }
        });

        if (chart) {
            chart.data = {
                labels: [],
                datasets: [{
                    label: 'Portfolio Value',
                    data: [],
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4
                }]
            };
            chart.update();
        }

        return chart;
    }

    // Create asset allocation chart
    createAssetAllocationChart(containerId, assets) {
        const chart = this.createChart(containerId, 'doughnut');

        if (chart) {
            const labels = assets.map(asset => asset.symbol);
            const data = assets.map(asset => asset.value);
            const backgroundColors = this.generateColorPalette(assets.length);

            chart.data = {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: backgroundColors,
                    borderWidth: 2,
                    borderColor: '#1a202c'
                }]
            };
            chart.options = {
                ...chart.options,
                plugins: {
                    ...chart.options.plugins,
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#e2e8f0',
                            padding: 20
                        }
                    }
                }
            };
            chart.update();
        }

        return chart;
    }

    // Generate color palette
    generateColorPalette(count) {
        const colors = [];
        const hueStep = 360 / count;
        
        for (let i = 0; i < count; i++) {
            const hue = (i * hueStep) % 360;
            // Create HSL color with good contrast
            colors.push(`hsl(${hue}, 70%, 60%)`);
        }
        
        return colors;
    }

    // Create security events chart
    createSecurityEventsChart(containerId, events) {
        const chart = this.createChart(containerId, 'bar');

        if (chart) {
            // Group events by type
            const eventCounts = {};
            events.forEach(event => {
                const type = event.event_type || 'Unknown';
                eventCounts[type] = (eventCounts[type] || 0) + 1;
            });

            const labels = Object.keys(eventCounts);
            const data = Object.values(eventCounts);
            const backgroundColors = this.generateColorPalette(labels.length);

            chart.data = {
                labels: labels,
                datasets: [{
                    label: 'Event Count',
                    data: data,
                    backgroundColor: backgroundColors,
                    borderColor: '#1a202c',
                    borderWidth: 1
                }]
            };
            chart.update();
        }

        return chart;
    }

    // Create VWAP chart
    createVwapChart(containerId, symbol, vwapData) {
        const chart = this.createChart(containerId, 'line');

        if (chart) {
            const timestamps = vwapData.map(item => item.timestamp);
            const vwapValues = vwapData.map(item => item.vwap);

            chart.data = {
                labels: timestamps,
                datasets: [{
                    label: `${symbol} VWAP`,
                    data: vwapValues,
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            };
            chart.update();
        }

        return chart;
    }
}

class DataManager {
    constructor() {
        this.dataCache = new Map();
        this.updateCallbacks = new Map();
    }

    // Cache data with expiration
    setCachedData(key, data, ttl = 300000) { // 5 minutes default TTL
        this.dataCache.set(key, {
            data,
            timestamp: Date.now(),
            ttl
        });
    }

    // Get cached data if not expired
    getCachedData(key) {
        const cached = this.dataCache.get(key);
        if (!cached) return null;

        if (Date.now() - cached.timestamp > cached.ttl) {
            this.dataCache.delete(key);
            return null;
        }

        return cached.data;
    }

    // Register update callback
    onUpdate(key, callback) {
        if (!this.updateCallbacks.has(key)) {
            this.updateCallbacks.set(key, []);
        }
        this.updateCallbacks.get(key).push(callback);
    }

    // Notify update subscribers
    notifyUpdate(key, data) {
        const callbacks = this.updateCallbacks.get(key);
        if (callbacks) {
            callbacks.forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error('Error in update callback:', error);
                }
            });
        }
    }

    // Get market data with caching
    async getMarketData(apiClient, useCache = true) {
        const cacheKey = 'market_data';
        
        if (useCache) {
            const cached = this.getCachedData(cacheKey);
            if (cached) return cached;
        }

        try {
            const response = await apiClient.getMarketOverview();
            this.setCachedData(cacheKey, response);
            this.notifyUpdate(cacheKey, response);
            return response;
        } catch (error) {
            console.error('Error fetching market data:', error);
            return null;
        }
    }

    // Get portfolio data with caching
    async getPortfolioData(apiClient, userId, useCache = true) {
        const cacheKey = `portfolio_${userId}`;
        
        if (useCache) {
            const cached = this.getCachedData(cacheKey);
            if (cached) return cached;
        }

        try {
            // Only fetch portfolio data if userId is valid
            if (!userId || userId === 'null') {
                return { portfolio: { total_value: 0, assets: [], transactions: [] } }; // Return empty portfolio
            }
            const response = await apiClient.getUserPortfolio(userId);
            this.setCachedData(cacheKey, response);
            this.notifyUpdate(cacheKey, response);
            return response;
        } catch (error) {
            console.error('Error fetching portfolio data:', error);
            return null;
        }
    }

    // Get security events with caching
    async getSecurityEvents(apiClient, useCache = true) {
        const cacheKey = 'security_events';
        
        if (useCache) {
            const cached = this.getCachedData(cacheKey);
            if (cached) return cached;
        }

        try {
            const response = await apiClient.getSecurityEvents();
            this.setCachedData(cacheKey, response);
            this.notifyUpdate(cacheKey, response);
            return response;
        } catch (error) {
            console.error('Error fetching security events:', error);
            return null;
        }
    }

    // Get user orders with caching
    async getUserOrders(apiClient, useCache = true) {
        const cacheKey = 'user_orders';
        
        if (useCache) {
            const cached = this.getCachedData(cacheKey);
            if (cached) return cached;
        }

        try {
            const response = await apiClient.getUserOrders();
            this.setCachedData(cacheKey, response);
            this.notifyUpdate(cacheKey, response);
            return response;
        } catch (error) {
            console.error('Error fetching user orders:', error);
            return null;
        }
    }
}

class RealTimeUpdater {
    constructor(apiClient, chartManager, dataManager) {
        this.apiClient = apiClient;
        this.chartManager = chartManager;
        this.dataManager = dataManager;
        this.updateIntervals = new Map();
        this.webSocket = null;
    }

    // Start real-time updates for a specific view
    startUpdates(viewName, updateInterval = 10000) {
        const intervalKey = `${viewName}_updates`;
        
        if (this.updateIntervals.has(intervalKey)) {
            // Already running, stop first
            this.stopUpdates(viewName);
        }

        const interval = setInterval(async () => {
            try {
                await this.updateViewData(viewName);
            } catch (error) {
                console.error(`Error updating ${viewName} data:`, error);
            }
        }, updateInterval);

        this.updateIntervals.set(intervalKey, interval);
    }

    // Stop real-time updates for a specific view
    stopUpdates(viewName) {
        const intervalKey = `${viewName}_updates`;
        const interval = this.updateIntervals.get(intervalKey);
        
        if (interval) {
            clearInterval(interval);
            this.updateIntervals.delete(intervalKey);
        }
    }

    // Update data for specific view
    async updateViewData(viewName) {
        switch (viewName) {
            case 'dashboard':
                await this.updateDashboardData();
                break;
            case 'trading':
                await this.updateTradingData();
                break;
            case 'security':
                await this.updateSecurityData();
                break;
            default:
                console.warn(`Unknown view: ${viewName}`);
        }
    }

    // Update dashboard data
    async updateDashboardData() {
        const [marketData, securityEvents, portfolio, orders] = await Promise.allSettled([
            this.dataManager.getMarketData(this.apiClient, false),
            this.dataManager.getSecurityEvents(this.apiClient, false),
            this.dataManager.getPortfolioData(this.apiClient, localStorage.getItem('user_id') || null, false),
            this.dataManager.getUserOrders(this.apiClient, false)
        ]);

        // Update charts if they exist
        if (marketData.status === 'fulfilled' && marketData.value) {
            this.updateMarketCharts(marketData.value.market_data);
        }

        if (securityEvents.status === 'fulfilled' && securityEvents.value) {
            this.updateSecurityCharts(securityEvents.value.events);
        }

        if (portfolio.status === 'fulfilled' && portfolio.value) {
            this.updatePortfolioCharts(portfolio.value.portfolio);
        }
    }

    // Update trading data
    async updateTradingData() {
        const marketData = await this.dataManager.getMarketData(this.apiClient, false);
        if (marketData) {
            this.updateMarketCharts(marketData.market_data);
        }

        const orders = await this.dataManager.getUserOrders(this.apiClient, false);
        if (orders) {
            this.updateOrdersTable(orders.orders);
        }
    }

    // Update security data
    async updateSecurityData() {
        const securityEvents = await this.dataManager.getSecurityEvents(this.apiClient, false);
        if (securityEvents) {
            this.updateSecurityCharts(securityEvents.events);
            this.updateSecurityStats(securityEvents.events);
        }
    }

    // Update market charts
    updateMarketCharts(marketData) {
        if (!marketData) return;

        for (const [symbol, data] of Object.entries(marketData)) {
            const chartContainerId = `market-chart-${symbol}`;
            
            // Create chart if it doesn't exist
            if (!this.chartManager.charts.has(chartContainerId)) {
                const container = domUtils.getElement(chartContainerId);
                if (container) {
                    this.chartManager.createMarketPriceChart(chartContainerId, symbol);
                }
            }

            // Update chart with current price
            if (data.vwap) {
                this.chartManager.updateMarketPriceChart(chartContainerId, data.vwap);
            }
        }
    }

    // Update security charts
    updateSecurityCharts(events) {
        if (!events || events.length === 0) return;

        // Update security events chart
        const securityChartContainer = domUtils.getElement('security-events-chart');
        if (securityChartContainer && !this.chartManager.charts.has('security-events-chart')) {
            this.chartManager.createSecurityEventsChart('security-events-chart', events);
        }
    }

    // Update portfolio charts
    updatePortfolioCharts(portfolio) {
        if (!portfolio) return;

        // Update portfolio value chart
        const portfolioChartContainer = domUtils.getElement('portfolio-value-chart');
        if (portfolioChartContainer && !this.chartManager.charts.has('portfolio-value-chart')) {
            this.chartManager.createPortfolioChart('portfolio-value-chart');
        }

        // Update portfolio value if available
        if (portfolio.total_value && this.chartManager.charts.has('portfolio-value-chart')) {
            const now = new Date();
            const timeLabel = `${now.getHours()}:${now.getMinutes()}`;
            this.chartManager.addDataPoint('portfolio-value-chart', 0, timeLabel, portfolio.total_value);
        }

        // Update asset allocation chart
        const allocationChartContainer = domUtils.getElement('asset-allocation-chart');
        if (allocationChartContainer && !this.chartManager.charts.has('asset-allocation-chart')) {
            this.chartManager.createAssetAllocationChart('asset-allocation-chart', portfolio.assets || []);
        }
    }

    // Update orders table
    updateOrdersTable(orders) {
        if (!orders) return;

        const table = domUtils.getElement('recent-orders-table');
        if (!table) return;

        const tbody = table.querySelector('tbody');
        if (!tbody) return;

        // Only update the table, don't recreate it to preserve performance
        // This would be implemented in the main app file
    }

    // Update security stats
    updateSecurityStats(events) {
        if (!events) return;

        const blockedCount = events.filter(e => 
            e.event_type.includes('BLOCKED') || e.event_type.includes('DETECTED')
        ).length;

        const attacksBlockedEl = domUtils.getElement('security-stats-attacks-blocked');
        if (attacksBlockedEl) {
            attacksBlockedEl.textContent = blockedCount;
        }
    }

    // Set up WebSocket connection for real-time updates
    setupWebSocket(userId) {
        if (this.webSocket) {
            this.webSocket.close();
        }

        if (!userId) return;

        try {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            this.webSocket = new WebSocket(`${protocol}//${window.location.host}/ws/${userId}`);

            this.webSocket.onopen = () => {
                console.log('Real-time updates WebSocket connected for user:', userId);
            };

            this.webSocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleRealTimeData(data);
                } catch (error) {
                    console.error('Error parsing WebSocket message:', error);
                }
            };

            this.webSocket.onclose = (event) => {
                console.log('Real-time updates WebSocket disconnected:', event.code, event.reason);
                // Attempt to reconnect after a delay
                setTimeout(() => {
                    this.setupWebSocket(userId);
                }, 5000);
            };

            this.webSocket.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
        } catch (error) {
            console.error('Failed to create WebSocket connection:', error);
        }
    }

    // Handle real-time data from WebSocket
    handleRealTimeData(data) {
        switch (data.type) {
            case 'market_update':
                if (data.payload && data.payload.market_data) {
                    this.updateMarketCharts(data.payload.market_data);
                }
                break;
            case 'order_update':
                // Update order-related components
                break;
            case 'security_event':
                if (data.payload && data.payload.event) {
                    this.updateSecurityCharts([data.payload.event]);
                    this.updateSecurityStats([data.payload.event]);
                }
                break;
            default:
                console.log('Unknown real-time data type:', data.type);
        }
    }

    // Clean up resources
    cleanup() {
        // Clear all intervals
        for (const [key, interval] of this.updateIntervals) {
            clearInterval(interval);
        }
        this.updateIntervals.clear();

        // Close WebSocket if open
        if (this.webSocket) {
            this.webSocket.close();
        }
    }
}

// Export visualization components
export {
    ChartManager,
    DataManager,
    RealTimeUpdater
};

// Create global instances
const chartManager = new ChartManager();
const dataManager = new DataManager();
const realTimeUpdater = new RealTimeUpdater(null, chartManager, dataManager);

// Make them available globally
window.visualization = {
    chartManager,
    dataManager,
    realTimeUpdater
};

console.log('Visualization module loaded');