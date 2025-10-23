/**
 * Main Application File for Secure Trading Platform
 * Fixed version with proper error handling and data flow
 */

// Import required modules
import { apiClient } from '/static/api/apiService.js';
import { domUtils, formUtils, dateUtils, numberUtils, uiUtils, validationRules, eventUtils, cryptoUtils } from '/static/js/utils.js';
import { TableComponent, CardComponent, ChartComponent, ModalComponent, FormComponent, TabComponent, ToastComponent, ProgressBarComponent, ListComponent } from '/static/js/components.js';

// Main application class
// =========================
// SecureTradingApp Class
// =========================
// Main SPA logic for Secure Stock Trading Exchange
// Handles authentication, navigation, data loading, UI updates, and security simulations
class SecureTradingApp {
    // =========================
    // Constructor & Properties
    // =========================
    constructor() {
        this.currentUser = null;
        this.isLoggedIn = false;
        this.currentView = 'dashboard';
        this.toast = new ToastComponent();
        this.toast.init();
        this.isInitialized = false;
        this.charts = new Map();
        this.updateIntervals = new Map();
        this.ws = null;
        this.userId = null;
    }

    // =========================
    // Initialization
    // =========================
    async init() {
        if (this.isInitialized) return;
        
        console.log('Initializing Secure Trading Platform...');
        
        // Set up DOM elements
        this.setupElements();
        
        // Set up event listeners
        this.setupEventListeners();
        
        // Check authentication status
        await this.checkAuthStatus();
        
        // Initialize all views
        await this.initializeViews();
        
        this.isInitialized = true;
        
        console.log('Secure Trading Platform initialized successfully');
    }

    // =========================
    // DOM Setup
    // =========================
    setupElements() {
        // Views
        this.views = {
            dashboard: domUtils.getElement('dashboard-view'),
            trading: domUtils.getElement('trading-view'),
            security: domUtils.getElement('security-view'),
            crypto: domUtils.getElement('crypto-view'),
            logs: domUtils.getElement('logs-view'),
            simulations: domUtils.getElement('simulations-view')
        };
        
        // Forms
        this.forms = {
            login: domUtils.getElement('login-form'),
            register: domUtils.getElement('register-form'),
            order: domUtils.getElement('order-form'),
            tradingOrder: domUtils.getElement('trading-order-form')
        };
        
        // Buttons
        this.buttons = {
            logout: domUtils.getElement('logout-btn'),
            showLoginTab: domUtils.getElement('show-login-tab'),
            showRegisterTab: domUtils.getElement('show-register-tab'),
            sqlInjectionSim: domUtils.getElement('sql-injection-sim-btn'),
            bruteForceSim: domUtils.getElement('brute-force-sim-btn'),
            replayAttackSim: domUtils.getElement('replay-attack-sim-btn'),
            mitmAttackSim: domUtils.getElement('mitm-attack-sim-btn')
        };
        
        // Elements
        this.elements = {
            authView: domUtils.getElement('auth-view'),
            mainView: domUtils.getElement('main-view'),
            messageArea: domUtils.getElement('message-area'),
            authMessageArea: domUtils.getElement('auth-message-area'),
            currentUsername: domUtils.getElement('current-username'),
            currentUserRole: domUtils.getElement('current-user-role'),
            currentUserBalance: domUtils.getElement('current-user-balance'),
            marketDataTable: domUtils.getElement('market-data-table'),
            recentOrdersTable: domUtils.getElement('recent-orders-table'),
            securityEventsContainer: domUtils.getElement('security-events-container'),
            sidebar: domUtils.getElement('sidebar'),
            orderAsset: domUtils.getElement('order-asset'),
            tradingAsset: domUtils.getElement('trading-asset')
        };
    }

    // =========================
    // Event Listeners
    // =========================
    setupEventListeners() {
        // Authentication
        if (this.forms.login) {
            this.forms.login.addEventListener('submit', (e) => this.handleLogin(e));
        }
        
        if (this.forms.register) {
            this.forms.register.addEventListener('submit', (e) => this.handleRegister(e));
        }
        
        // Navigation
        const navLinks = domUtils.queryAll('.nav-link');
        navLinks.forEach(link => {
            link.addEventListener('click', (e) => this.handleNavigation(e));
        });
        
        // Logout
        if (this.buttons.logout) {
            this.buttons.logout.addEventListener('click', () => this.handleLogout());
        }
        
        // Tab switching
        if (this.buttons.showLoginTab) {
            this.buttons.showLoginTab.addEventListener('click', () => this.showLoginTab());
        }
        
        if (this.buttons.showRegisterTab) {
            this.buttons.showRegisterTab.addEventListener('click', () => this.showRegisterTab());
        }
        
        // Order forms
        if (this.forms.order) {
            this.forms.order.addEventListener('submit', (e) => this.handleOrder(e));
        }
        
        if (this.forms.tradingOrder) {
            this.forms.tradingOrder.addEventListener('submit', (e) => this.handleTradingOrder(e));
        }
        
        // Order book symbol selector
        const orderbookSymbolSelect = domUtils.getElement('orderbook-symbol-select');
        if (orderbookSymbolSelect) {
            orderbookSymbolSelect.addEventListener('change', (e) => {
                this.updateOrderBook(e.target.value);
            });
        }
        
        // Trading asset selector - sync with order book
        const tradingAssetSelect = domUtils.getElement('trading-asset');
        if (tradingAssetSelect) {
            tradingAssetSelect.addEventListener('change', (e) => {
                const symbol = e.target.value;
                if (symbol && orderbookSymbolSelect) {
                    orderbookSymbolSelect.value = symbol;
                    this.updateOrderBook(symbol);
                }
            });
        }
        
        // Simulation buttons
        if (this.buttons.sqlInjectionSim) {
            this.buttons.sqlInjectionSim.addEventListener('click', () => this.handleSqlInjectionSim());
        }
        
        if (this.buttons.bruteForceSim) {
            this.buttons.bruteForceSim.addEventListener('click', () => this.handleBruteForceSim());
        }
        
        if (this.buttons.replayAttackSim) {
            this.buttons.replayAttackSim.addEventListener('click', () => this.handleReplayAttackSim());
        }
        
        if (this.buttons.mitmAttackSim) {
            this.buttons.mitmAttackSim.addEventListener('click', () => this.handleMitmAttackSim());
        }
        
        // Crypto demo buttons
        this.setupCryptoDemoEventListeners();
        
        // Logs tabs
        this.setupLogsTabListeners();
    }

    // =========================
    // Authentication
    // =========================
    async checkAuthStatus() {
        const token = localStorage.getItem('auth_token');
        if (token) {
            try {
                // Verify token by fetching user data
                const orders = await apiClient.getUserOrders();
                if (orders && !orders.error) {
                    this.isLoggedIn = true;
                    this.showMainView();
                    await this.loadUserData();
                } else {
                    throw new Error('Invalid token');
                }
            } catch (error) {
                console.error('Token verification failed:', error);
                localStorage.removeItem('auth_token');
                localStorage.removeItem('user_id');
                this.isLoggedIn = false;
                this.showAuthView();
            }
        } else {
            this.isLoggedIn = false;
            this.showAuthView();
        }
    }

    // Handle login form submit
    async handleLogin(e) {
        e.preventDefault();
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value;
        // Username must be alphanumeric, 3-20 chars
        if (!username.match(/^[a-zA-Z0-9_]{3,20}$/)) {
            this.toast.show('Username must be 3-20 characters, letters/numbers/underscores only', 'danger');
            return;
        }
        // Password must be at least 8 chars, contain a number and a letter
        if (!password.match(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*]{8,}$/)) {
            this.toast.show('Password must be at least 8 characters and contain a letter and a number', 'danger');
            return;
        }
        try {
            uiUtils.showLoading();
            const result = await apiClient.login(username, password);
            if (result.success) {
                this.isLoggedIn = true;
                this.userId = result.user_id;
                this.showMainView();
                await this.loadUserData();
                this.startRealTimeUpdates();
                this.toast.show('Login successful', 'success');
            } else {
                this.toast.show(result.message || 'Login failed', 'danger');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.toast.show('Login failed: ' + error.message, 'danger');
        } finally {
            uiUtils.hideLoading();
        }
    }

    // Handle registration form submit
    async handleRegister(e) {
        e.preventDefault();
        const username = document.getElementById('register-username').value.trim();
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;
        // Username must be alphanumeric, 3-20 chars
        if (!username.match(/^[a-zA-Z0-9_]{3,20}$/)) {
            this.toast.show('Username must be 3-20 characters, letters/numbers/underscores only', 'danger');
            return;
        }
        // Password must be at least 8 chars, contain a number and a letter
        if (!password.match(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*]{8,}$/)) {
            this.toast.show('Password must be at least 8 characters and contain a letter and a number', 'danger');
            return;
        }
        if (password !== confirmPassword) {
            this.toast.show('Passwords do not match', 'danger');
            return;
        }
        try {
            uiUtils.showLoading();
            const result = await apiClient.register(username, password);
            if (result.success) {
                this.toast.show('Registration successful! Please log in.', 'success');
                this.showLoginTab();
            } else {
                this.toast.show(result.message || 'Registration failed', 'danger');
            }
        } catch (error) {
            console.error('Registration error:', error);
            this.toast.show('Registration failed: ' + error.message, 'danger');
        } finally {
            uiUtils.hideLoading();
        }
    }

    // Handle logout button click
    async handleLogout() {
        try {
            this.stopRealTimeUpdates();
            await apiClient.logout();
            this.isLoggedIn = false;
            this.currentUser = null;
            this.userId = null;
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user_id');
            this.showAuthView();
            this.toast.show('Logged out successfully', 'success');
        } catch (error) {
            console.error('Logout error:', error);
            this.toast.show('Logout failed: ' + error.message, 'danger');
        }
    }

    // =========================
    // Order Placement
    // =========================
    async handleOrder(e) {
        e.preventDefault();
        const symbol = document.getElementById('order-asset').value;
        const side = document.getElementById('order-type').value;
        const quantity = parseFloat(document.getElementById('order-amount').value);
        const price = parseFloat(document.getElementById('order-price').value);
        // Validate asset
        if (!symbol) {
            this.toast.show('Please select an asset', 'danger');
            return;
        }
        // Validate side
        if (!['buy','sell'].includes(side)) {
            this.toast.show('Order type must be BUY or SELL', 'danger');
            return;
        }
        // Validate quantity and price
        if (isNaN(quantity) || quantity <= 0) {
            this.toast.show('Quantity must be a positive number', 'danger');
            return;
        }
        if (isNaN(price) || price <= 0) {
            this.toast.show('Price must be a positive number', 'danger');
            return;
        }
        try {
            uiUtils.showLoading();
            const result = await apiClient.createOrder(symbol, side, quantity, price);
            if (result.success) {
                this.toast.show(`Order placed successfully for ${quantity} ${symbol}`, 'success');
                await this.loadRecentOrders();
                document.getElementById('order-form').reset();
            } else {
                this.toast.show(result.message || 'Order placement failed', 'danger');
            }
        } catch (error) {
            console.error('Order error:', error);
            this.toast.show('Order placement failed: ' + error.message, 'danger');
        } finally {
            uiUtils.hideLoading();
        }
    }

    // Handle trading order form submit
    async handleTradingOrder(e) {
        e.preventDefault();
        
        const symbol = document.getElementById('trading-asset').value;
        const side = document.getElementById('trading-type').value;
        const quantity = parseFloat(document.getElementById('trading-amount').value);
        const price = parseFloat(document.getElementById('trading-price').value);
        
        if (!symbol || !side || !quantity || !price) {
            this.toast.show('Please fill all order fields', 'danger');
            return;
        }
        
        try {
            uiUtils.showLoading();
            
            const result = await apiClient.createOrder(symbol, side, quantity, price);
            
            if (result.success) {
                this.toast.show(`✅ Order placed: ${side.toUpperCase()} ${quantity} ${symbol} @ $${price}`, 'success');
                
                // Refresh order book for this symbol
                await this.updateOrderBook(symbol);
                
                // Refresh portfolio and trading data
                await this.loadTradingData();
                
                // Reset form
                document.getElementById('trading-order-form').reset();
                
                // Reselect the symbol in the dropdown
                const tradingAsset = document.getElementById('trading-asset');
                if (tradingAsset) tradingAsset.value = symbol;
                
                // Keep order book showing the same symbol
                const orderbookSelect = document.getElementById('orderbook-symbol-select');
                if (orderbookSelect) orderbookSelect.value = symbol;
            } else {
                this.toast.show(result.message || 'Order placement failed', 'danger');
            }
        } catch (error) {
            console.error('Trading order error:', error);
            this.toast.show('Order placement failed: ' + error.message, 'danger');
        } finally {
            uiUtils.hideLoading();
        }
    }

    // =========================
    // Navigation & View Switching
    // =========================
    handleNavigation(e) {
        e.preventDefault();
        const target = e.target.closest('a');
        if (!target) return;
        
        const view = target.getAttribute('href').substring(1);
        this.switchView(view);
    }

    // Switch between main views
    switchView(viewName) {
        // Hide all views
        for (const viewKey in this.views) {
            if (this.views[viewKey]) {
                domUtils.hide(this.views[viewKey]);
            }
        }
        
        // Show selected view
        if (this.views[viewName]) {
            domUtils.show(this.views[viewName]);
        }
        
        this.currentView = viewName;
        
        // Load view-specific data
        this.loadViewData(viewName);
        
        // Update active nav link
        const navLinks = domUtils.queryAll('.nav-link');
        navLinks.forEach(link => {
            if (link.getAttribute('href') === `#${viewName}`) {
                domUtils.addClass(link, 'active');
                domUtils.removeClass(link, 'text-gray-400');
                domUtils.addClass(link, 'text-green-400');
            } else {
                domUtils.removeClass(link, 'active');
                domUtils.removeClass(link, 'text-green-400');
                domUtils.addClass(link, 'text-gray-400');
            }
        });
    }

    // Load data for the selected view
    async loadViewData(viewName) {
        switch (viewName) {
            case 'dashboard':
                await this.loadDashboardData();
                break;
            case 'trading':
                await this.loadTradingData();
                break;
            case 'security':
                await this.loadSecurityData();
                break;
            case 'crypto':
                await this.loadCryptoData();
                break;
            case 'logs':
                await this.loadLogsData();
                break;
            case 'simulations':
                await this.loadSimulationsData();
                break;
        }
    }

    // Show authentication view (login/register)
    showAuthView() {
        if (this.elements.mainView) domUtils.hide(this.elements.mainView);
        if (this.elements.authView) domUtils.show(this.elements.authView);
    }

    // Show main application view (dashboard, trading, etc.)
    showMainView() {
        if (this.elements.authView) domUtils.hide(this.elements.authView);
        if (this.elements.mainView) domUtils.show(this.elements.mainView);
    }

    // Show login tab in auth view
    showLoginTab() {
        const loginForm = domUtils.getElement('login-form');
        const registerForm = domUtils.getElement('register-form');
        
        if (loginForm) domUtils.removeClass(loginForm, 'hidden');
        if (registerForm) domUtils.addClass(registerForm, 'hidden');
        
        const loginTab = domUtils.getElement('show-login-tab');
        const registerTab = domUtils.getElement('show-register-tab');
        
        if (loginTab) {
            domUtils.addClass(loginTab, 'bg-green-500', 'text-black');
            domUtils.removeClass(loginTab, 'text-gray-400');
        }
        if (registerTab) {
            domUtils.removeClass(registerTab, 'bg-green-500', 'text-black');
            domUtils.addClass(registerTab, 'text-gray-400');
        }
    }

    // Show register tab in auth view
    showRegisterTab() {
        const loginForm = domUtils.getElement('login-form');
        const registerForm = domUtils.getElement('register-form');
        
        if (registerForm) domUtils.removeClass(registerForm, 'hidden');
        if (loginForm) domUtils.addClass(loginForm, 'hidden');
        
        const loginTab = domUtils.getElement('show-login-tab');
        const registerTab = domUtils.getElement('show-register-tab');
        
        if (registerTab) {
            domUtils.addClass(registerTab, 'bg-green-500', 'text-black');
            domUtils.removeClass(registerTab, 'text-gray-400');
        }
        if (loginTab) {
            domUtils.removeClass(loginTab, 'bg-green-500', 'text-black');
            domUtils.addClass(loginTab, 'text-gray-400');
        }
    }

    // =========================
    // User Data & Assets
    // =========================
    // Load user data after login
    async loadUserData() {
        try {
            const userId = localStorage.getItem('user_id');
            if (userId) {
                this.userId = userId;
                if (this.elements.currentUsername) {
                    this.elements.currentUsername.textContent = `User${userId}`;
                }
                if (this.elements.currentUserRole) {
                    this.elements.currentUserRole.textContent = 'trader';
                }
            }
            
            // Load initial dashboard data
            await this.loadDashboardData();
        } catch (error) {
            console.error('Error loading user data:', error);
        }
    }

    // Initialize all views (load assets, etc.)
    async initializeViews() {
        await this.loadAssets();
    }

    // Load assets for order/trading forms
    async loadAssets() {
        const assets = [
            { symbol: 'BTC', name: 'Bitcoin' },
            { symbol: 'ETH', name: 'Ethereum' },
            { symbol: 'ADA', name: 'Cardano' },
            { symbol: 'DOT', name: 'Polkadot' },
            { symbol: 'SOL', name: 'Solana' },
            { symbol: 'XRP', name: 'Ripple' },
            { symbol: 'AVAX', name: 'Avalanche' },
            { symbol: 'LINK', name: 'Chainlink' }
        ];
        
        // Populate order form asset dropdown
        if (this.elements.orderAsset) {
            this.elements.orderAsset.innerHTML = '<option value="">Select Asset</option>';
            assets.forEach(asset => {
                const option = document.createElement('option');
                option.value = asset.symbol;
                option.textContent = `${asset.symbol} - ${asset.name}`;
                this.elements.orderAsset.appendChild(option);
            });
        }
        
        // Populate trading form asset dropdown
        if (this.elements.tradingAsset) {
            this.elements.tradingAsset.innerHTML = '<option value="">Select Asset</option>';
            assets.forEach(asset => {
                const option = document.createElement('option');
                option.value = asset.symbol;
                option.textContent = `${asset.symbol} - ${asset.name}`;
                this.elements.tradingAsset.appendChild(option);
            });
        }
    }

    // =========================
    // Dashboard & Data Loading
    // =========================
    // Load dashboard data (all stats dynamic)
    async loadDashboardData() {
        try {
            const [marketData, orders, securityEvents, portfolio, stats] = await Promise.allSettled([
                apiClient.getMarketOverview(),
                apiClient.getUserOrders(),
                apiClient.getSecurityEvents(),
                apiClient.getUserPortfolio(this.userId),
                apiClient.request('/api/data/stats')
            ]);

            // Update market data table
            if (marketData.status === 'fulfilled' && marketData.value && marketData.value.market_data) {
                this.updateMarketTable(marketData.value.market_data);
            }

            // Update recent orders table
            if (orders.status === 'fulfilled' && orders.value && orders.value.orders) {
                this.updateRecentOrdersTable(orders.value.orders);
            }

            // Update security events
            if (securityEvents.status === 'fulfilled' && securityEvents.value && securityEvents.value.events) {
                this.updateSecurityEvents(securityEvents.value.events);
            }

            // Update portfolio info
            if (portfolio.status === 'fulfilled' && portfolio.value && portfolio.value.portfolio) {
                this.updatePortfolioInfo(portfolio.value.portfolio);
            }

            // Update dashboard stats
            if (stats.status === 'fulfilled' && stats.value) {
                this.updateDashboardStats(stats.value);
            }

            // Update system status
            this.updateSystemStatus();
            
            // Update order book with selected symbol (default BTC)
            const orderbookSelect = domUtils.getElement('orderbook-symbol-select');
            const selectedSymbol = orderbookSelect?.value || 'BTC';
            this.updateOrderBook(selectedSymbol);
        } catch (error) {
            console.error('Error loading dashboard data:', error);
        }
    }
    // Update dashboard stats (orders today, active users, system load, response time, 24h change, performance)
    updateDashboardStats(stats) {
        const ordersToday = domUtils.getElement('stats-orders-today');
        const activeUsers = domUtils.getElement('stats-active-users');
        const systemLoad = domUtils.getElement('stats-system-load');
        const responseTime = domUtils.getElement('stats-response-time');
        const change = domUtils.getElement('dashboard-24h-change');
        const performance = domUtils.getElement('dashboard-performance');

        if (ordersToday && stats.orders_today !== undefined) ordersToday.textContent = stats.orders_today;
        if (activeUsers && stats.active_users !== undefined) activeUsers.textContent = stats.active_users;
        if (systemLoad && stats.system_load !== undefined) systemLoad.textContent = stats.system_load;
        if (responseTime && stats.response_time !== undefined) responseTime.textContent = stats.response_time + 'ms';
        if (change && stats.change_24h !== undefined) change.textContent = (stats.change_24h >= 0 ? '+' : '') + numberUtils.formatPercentage(stats.change_24h, 2);
        if (performance && stats.performance !== undefined) performance.textContent = stats.performance;
    }

    // Update market data table
    updateMarketTable(marketData) {
        const tbody = this.elements.marketDataTable?.querySelector('tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (!marketData || Object.keys(marketData).length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-2 text-center text-gray-400">No market data available</td></tr>';
            return;
        }
        
        Object.entries(marketData).forEach(([symbol, data]) => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-800';
            
            const change = data.change || 0;
            const changeClass = change >= 0 ? 'text-green-400' : 'text-red-400';
            const changePrefix = change >= 0 ? '+' : '';
            
            tr.innerHTML = `
                <td class="py-2 text-green-400">${symbol}</td>
                <td class="py-2 text-right">${numberUtils.formatCurrency(data.vwap || data.price || 0, 2)}</td>
                <td class="py-2 text-right ${changeClass}">${changePrefix}${numberUtils.formatPercentage(change, 2)}</td>
                <td class="py-2 text-right">${numberUtils.formatNumber(data.volume || 0)}</td>
                <td class="py-2 text-right">${numberUtils.formatCurrency(data.vwap || data.price || 0, 2)}</td>
            `;
            
            tbody.appendChild(tr);
        });
    }

    // Update recent orders table
    updateRecentOrdersTable(orders) {
        const tbody = this.elements.recentOrdersTable?.querySelector('tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (!orders || orders.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-2 text-center text-gray-400">No recent orders</td></tr>';
            return;
        }
        
        orders.slice(0, 10).forEach(order => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-800';
            
            const sideClass = order.side === 'buy' ? 'text-green-400' : 'text-red-400';
            const statusClass = order.status === 'FILLED' ? 'text-green-400' : 'text-yellow-400';
            
            tr.innerHTML = `
                <td class="py-2 text-green-400">${order.id || 'N/A'}</td>
                <td class="py-2 text-blue-400">${order.symbol || 'N/A'}</td>
                <td class="py-2 ${sideClass}">${(order.side || 'N/A').toUpperCase()}</td>
                <td class="py-2">${order.quantity || '0'}</td>
                <td class="py-2 ${statusClass}">${order.status || 'PENDING'}</td>
            `;
            
            tbody.appendChild(tr);
        });
    }

    // Update order book display with improved formatting
    async updateOrderBook(symbol = 'BTC') {
        try {
            const orderBookData = await apiClient.getOrderBook(symbol);
            
            // Update sell orders (asks) - highest to lowest
            const sellOrdersList = domUtils.getElement('sell-orders-list');
            const sellOrdersCount = domUtils.getElement('sell-orders-count');
            
            if (sellOrdersList) {
                if (!orderBookData.sell_orders || orderBookData.sell_orders.length === 0) {
                    sellOrdersList.innerHTML = '<div class="text-center text-gray-500 py-4 text-sm">No sell orders</div>';
                    if (sellOrdersCount) sellOrdersCount.textContent = '0 orders';
                } else {
                    // Sort sell orders by price (descending - highest first)
                    const sortedSells = [...orderBookData.sell_orders].sort((a, b) => b.price - a.price);
                    
                    sellOrdersList.innerHTML = sortedSells.map(order => {
                        const total = order.price * order.quantity;
                        const barWidth = Math.min((order.quantity / Math.max(...sortedSells.map(o => o.quantity))) * 100, 100);
                        
                        return `
                            <div class="relative grid grid-cols-3 text-xs py-2 px-2 rounded hover:bg-gray-700 transition-colors cursor-pointer group">
                                <!-- Background bar -->
                                <div class="absolute inset-0 bg-red-900 opacity-10 rounded" style="width: ${barWidth}%"></div>
                                
                                <!-- Price -->
                                <div class="text-left text-red-400 font-semibold z-10">${numberUtils.formatCurrency(order.price, 2)}</div>
                                
                                <!-- Quantity -->
                                <div class="text-center text-gray-300 z-10">${numberUtils.formatNumber(order.quantity, 4)}</div>
                                
                                <!-- Total -->
                                <div class="text-right text-gray-400 z-10">${numberUtils.formatCurrency(total, 2)}</div>
                                
                                <!-- Hover tooltip -->
                                <div class="absolute left-0 top-full mt-1 hidden group-hover:block bg-gray-900 border border-gray-700 rounded p-2 text-xs z-20 whitespace-nowrap">
                                    <div class="text-gray-400">Orders: <span class="text-green-400">${order.count || 1}</span></div>
                                </div>
                            </div>
                        `;
                    }).join('');
                    
                    if (sellOrdersCount) sellOrdersCount.textContent = `${sortedSells.length} orders`;
                }
            }
            
            // Update buy orders (bids) - highest to lowest
            const buyOrdersList = domUtils.getElement('buy-orders-list');
            const buyOrdersCount = domUtils.getElement('buy-orders-count');
            
            if (buyOrdersList) {
                if (!orderBookData.buy_orders || orderBookData.buy_orders.length === 0) {
                    buyOrdersList.innerHTML = '<div class="text-center text-gray-500 py-4 text-sm">No buy orders</div>';
                    if (buyOrdersCount) buyOrdersCount.textContent = '0 orders';
                } else {
                    // Sort buy orders by price (descending - highest first)
                    const sortedBuys = [...orderBookData.buy_orders].sort((a, b) => b.price - a.price);
                    
                    buyOrdersList.innerHTML = sortedBuys.map(order => {
                        const total = order.price * order.quantity;
                        const barWidth = Math.min((order.quantity / Math.max(...sortedBuys.map(o => o.quantity))) * 100, 100);
                        
                        return `
                            <div class="relative grid grid-cols-3 text-xs py-2 px-2 rounded hover:bg-gray-700 transition-colors cursor-pointer group">
                                <!-- Background bar -->
                                <div class="absolute inset-0 bg-green-900 opacity-10 rounded" style="width: ${barWidth}%"></div>
                                
                                <!-- Price -->
                                <div class="text-left text-green-400 font-semibold z-10">${numberUtils.formatCurrency(order.price, 2)}</div>
                                
                                <!-- Quantity -->
                                <div class="text-center text-gray-300 z-10">${numberUtils.formatNumber(order.quantity, 4)}</div>
                                
                                <!-- Total -->
                                <div class="text-right text-gray-400 z-10">${numberUtils.formatCurrency(total, 2)}</div>
                                
                                <!-- Hover tooltip -->
                                <div class="absolute left-0 top-full mt-1 hidden group-hover:block bg-gray-900 border border-gray-700 rounded p-2 text-xs z-20 whitespace-nowrap">
                                    <div class="text-gray-400">Orders: <span class="text-green-400">${order.count || 1}</span></div>
                                </div>
                            </div>
                        `;
                    }).join('');
                    
                    if (buyOrdersCount) buyOrdersCount.textContent = `${sortedBuys.length} orders`;
                }
            }
            
            // Calculate and display spread
            const spreadValue = domUtils.getElement('spread-value');
            if (spreadValue && orderBookData.sell_orders?.length > 0 && orderBookData.buy_orders?.length > 0) {
                const lowestAsk = Math.min(...orderBookData.sell_orders.map(o => o.price));
                const highestBid = Math.max(...orderBookData.buy_orders.map(o => o.price));
                const spread = lowestAsk - highestBid;
                const spreadPercent = (spread / lowestAsk) * 100;
                
                spreadValue.textContent = `${numberUtils.formatCurrency(spread, 2)} (${numberUtils.formatPercentage(spreadPercent, 2)})`;
            } else if (spreadValue) {
                spreadValue.textContent = '--';
            }
            
            // Update last price (use midpoint of spread or last trade)
            const lastPrice = domUtils.getElement('last-price');
            if (lastPrice && orderBookData.sell_orders?.length > 0 && orderBookData.buy_orders?.length > 0) {
                const lowestAsk = Math.min(...orderBookData.sell_orders.map(o => o.price));
                const highestBid = Math.max(...orderBookData.buy_orders.map(o => o.price));
                const midPrice = (lowestAsk + highestBid) / 2;
                
                lastPrice.textContent = numberUtils.formatCurrency(midPrice, 2);
            } else if (lastPrice) {
                lastPrice.textContent = '--';
            }
            
            // Update 24h volume (simplified - sum of all order quantities)
            const volume24h = domUtils.getElement('24h-volume');
            if (volume24h) {
                const totalBuyQty = orderBookData.buy_orders?.reduce((sum, o) => sum + o.quantity, 0) || 0;
                const totalSellQty = orderBookData.sell_orders?.reduce((sum, o) => sum + o.quantity, 0) || 0;
                const totalVolume = totalBuyQty + totalSellQty;
                
                volume24h.textContent = totalVolume > 0 ? numberUtils.formatNumber(totalVolume, 2) : '--';
            }
        } catch (error) {
            console.error('Error updating order book:', error);
        }
    }

    // =========================
    // Security Events & Portfolio
    // =========================
    // Update security events
    updateSecurityEvents(events) {
        const container = this.elements.securityEventsContainer;
        if (!container) return;
        
        container.innerHTML = '';
        
        if (!events || events.length === 0) {
            container.innerHTML = '<div class="p-2 bg-gray-800 rounded"><div class="text-center text-gray-400">No security events</div></div>';
            return;
        }
        
        events.slice(0, 10).forEach(event => {
            const timestamp = dateUtils.formatTime(new Date(event.created_at || new Date()));
            
            const eventDiv = document.createElement('div');
            eventDiv.className = 'p-2 bg-gray-800 rounded mb-2';
            eventDiv.innerHTML = `
                <div class="flex justify-between">
                    <span class="text-green-400">${event.event_type || 'N/A'}</span>
                    <span class="text-gray-500">${timestamp}</span>
                </div>
                <div class="text-gray-400 text-sm">${event.description || 'No description'}</div>
            `;
            
            container.appendChild(eventDiv);
        });
    }

    // Update portfolio info
    updatePortfolioInfo(portfolio) {
        if (this.elements.currentUserBalance && portfolio.total_value !== undefined) {
            this.elements.currentUserBalance.textContent = numberUtils.formatNumber(portfolio.total_value, 2);
        }
        
        const dashboardBalance = domUtils.getElement('dashboard-balance');
        if (dashboardBalance && portfolio.total_value !== undefined) {
            dashboardBalance.textContent = numberUtils.formatCurrency(portfolio.total_value, 2);
        }
        
        const dashboardAssetCount = domUtils.getElement('dashboard-asset-count');
        if (dashboardAssetCount) {
            const count = Array.isArray(portfolio.assets) ? portfolio.assets.length : portfolio.asset_count || 0;
            dashboardAssetCount.textContent = count;
        }
    }

    // Update system status (Merkle root, etc.)
    updateSystemStatus() {
        const dashboardMerkleRoot = domUtils.getElement('dashboard-merkle-root');
        if (dashboardMerkleRoot) {
            dashboardMerkleRoot.textContent = cryptoUtils.generateRandomHex(16) + '...';
        }
    }

    // Load recent orders for user
    async loadRecentOrders() {
        try {
            const orders = await apiClient.getUserOrders();
            if (orders && orders.orders) {
                this.updateRecentOrdersTable(orders.orders);
            }
        } catch (error) {
            console.error('Error loading recent orders:', error);
        }
    }

    // Load trading data for trading view
    async loadTradingData() {
        try {
            const [marketData, orders, portfolio] = await Promise.allSettled([
                apiClient.getMarketOverview(),
                apiClient.getUserOrders(),
                apiClient.getUserPortfolio(this.userId)
            ]);
            
            if (portfolio.status === 'fulfilled' && portfolio.value && portfolio.value.portfolio) {
                this.updatePortfolioTable(portfolio.value.portfolio);
            }
        } catch (error) {
            console.error('Error loading trading data:', error);
        }
    }

    // Update portfolio table in trading view
    updatePortfolioTable(portfolio) {
        const table = domUtils.getElement('portfolio-table');
        if (!table) return;
        
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (!portfolio.assets || portfolio.assets.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="py-8 text-center">
                        <div class="text-gray-400 mb-2">📭 Your portfolio is empty</div>
                        <div class="text-sm text-gray-500">Place some buy orders to start building your portfolio</div>
                    </td>
                </tr>
            `;
            return;
        }
        
        portfolio.assets.forEach(asset => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-800 hover:bg-gray-800 transition-colors';
            
            const change = asset.change || 0;
            const changeClass = change >= 0 ? 'text-green-400' : 'text-red-400';
            const changePrefix = change >= 0 ? '+' : '';
            const changeIcon = change >= 0 ? '📈' : '📉';
            
            tr.innerHTML = `
                <td class="py-3">
                    <div class="text-green-400 font-semibold">${asset.symbol || 'N/A'}</div>
                    <div class="text-xs text-gray-500">${asset.name || ''}</div>
                </td>
                <td class="py-3 text-right text-gray-300">${numberUtils.formatNumber(asset.quantity || 0, 4)}</td>
                <td class="py-3 text-right">
                    <div class="text-gray-300">${numberUtils.formatCurrency(asset.price || 0, 2)}</div>
                    <div class="text-xs text-gray-500">Avg: ${numberUtils.formatCurrency(asset.avg_buy_price || 0, 2)}</div>
                </td>
                <td class="py-3 text-right text-gray-300 font-semibold">${numberUtils.formatCurrency(asset.total_value || 0, 2)}</td>
                <td class="py-3 text-right ${changeClass} font-semibold">
                    ${changeIcon} ${changePrefix}${numberUtils.formatPercentage(change, 2)}
                </td>
            `;
            
            tbody.appendChild(tr);
        });
    }

    // Load security data (events, blocked IPs)
    async loadSecurityData() {
        try {
            const [securityEvents, blockedIps] = await Promise.allSettled([
                apiClient.getSecurityEvents(),
                apiClient.getBlockedIps()
            ]);
            
            if (securityEvents.status === 'fulfilled' && securityEvents.value && securityEvents.value.events) {
                const events = securityEvents.value.events;
                const blockedCount = events.filter(e => e.event_type && e.event_type.includes('BLOCKED')).length;
                const activeThreats = events.filter(e => 
                    e.event_type && (e.event_type.includes('DETECTED') || e.event_type.includes('ATTEMPT'))
                ).length;
                
                const attacksBlockedEl = domUtils.getElement('security-stats-attacks-blocked');
                const activeThreatsEl = domUtils.getElement('security-stats-active-threats');
                
                if (attacksBlockedEl) attacksBlockedEl.textContent = blockedCount;
                if (activeThreatsEl) activeThreatsEl.textContent = activeThreats;
            }
            
            if (blockedIps.status === 'fulfilled' && blockedIps.value && blockedIps.value.blocked_ips) {
                this.updateBlockedIpsTable(blockedIps.value.blocked_ips);
            }
        } catch (error) {
            console.error('Error loading security data:', error);
        }
    }

    // Update blocked IPs table
    updateBlockedIpsTable(blockedIps) {
        const table = domUtils.getElement('blocked-ips-table');
        if (!table) return;
        
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (!blockedIps || blockedIps.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="py-2 text-center text-gray-400">No blocked IPs</td></tr>';
            return;
        }
        
        blockedIps.forEach(ip => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-800';
            
            tr.innerHTML = `
                <td class="py-2 text-green-400">${ip.ip_address || 'N/A'}</td>
                <td class="py-2">${ip.reason || 'N/A'}</td>
                <td class="py-2">${dateUtils.formatDateTime(ip.timestamp || new Date())}</td>
                <td class="py-2">
                    <button class="text-red-400 hover:text-red-300 text-sm" onclick="app.unblockIp('${ip.ip_address || ''}')">Unblock</button>
                </td>
            `;
            
            tbody.appendChild(tr);
        });
    }

    // Unblock IP address
    async unblockIp(ipAddress) {
        try {
            await apiClient.unblockIp(ipAddress);
            this.toast.show(`IP ${ipAddress} unblocked successfully`, 'success');
            this.loadSecurityData();
        } catch (error) {
            console.error('Error unblocking IP:', error);
            this.toast.show(`Failed to unblock IP: ${error.message}`, 'danger');
        }
    }

    // =========================
    // Crypto Demos
    // =========================
    // Load crypto data (client-side demos)
    async loadCryptoData() {
        // Crypto demos are client-side only
        console.log('Crypto demo view loaded');
    }

    // =========================
    // Logs & Simulations
    // =========================
    // Load logs data (all tabs)
    async loadLogsData() {
        try {
            // Load all logs in parallel
            const [userLogs, securityLogs, auditLogs] = await Promise.all([
                apiClient.getUserActivityLogs(),
                apiClient.getSecurityLogs(),
                apiClient.getAuditLogs(50)
            ]);

            if (userLogs && userLogs.logs) {
                this.updateUserLogsTable(userLogs.logs);
            }
            if (securityLogs && securityLogs.logs) {
                this.updateSecurityLogsTable(securityLogs.logs);
            }
            if (auditLogs && auditLogs.logs) {
                this.updateAuditLogsTable(auditLogs.logs);
            }
        } catch (error) {
            console.error('Error loading logs data:', error);
        }
    }

    // Update user logs table (limit to 10 latest)
    updateUserLogsTable(logs) {
        const tbody = domUtils.getElement('user-logs-table');
        if (!tbody) return;

        tbody.innerHTML = '';

        // Filter for login/logout events only
        const filteredLogs = logs ? logs.filter(log => log.event_type === 'USER_LOGIN' || log.event_type === 'USER_LOGOUT') : [];

        if (!filteredLogs || filteredLogs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="py-2 text-center text-gray-400">No login/logout logs available</td></tr>';
            return;
        }

        filteredLogs.slice(0, 10).forEach(log => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-800';

            tr.innerHTML = `
                <td class="py-2 text-green-400">${log.id || 'N/A'}</td>
                <td class="py-2 text-blue-400">${log.event_type || 'N/A'}</td>
                <td class="py-2">${log.description || 'N/A'}</td>
                <td class="py-2">${dateUtils.formatDateTime(log.created_at || new Date())}</td>
            `;

            tbody.appendChild(tr);
        });
    }

    // Update security logs table (limit to 10 latest)
    updateSecurityLogsTable(logs) {
        const tbody = domUtils.getElement('security-logs-table');
        if (!tbody) return;

        tbody.innerHTML = '';

        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="py-2 text-center text-gray-400">No security logs available</td></tr>';
            return;
        }

        logs.slice(0, 10).forEach(log => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-800';
            tr.innerHTML = `
                <td class="py-2 text-green-400">${log.id || 'N/A'}</td>
                <td class="py-2 text-blue-400">${log.event_type || 'N/A'}</td>
                <td class="py-2">${log.description || 'N/A'}</td>
                <td class="py-2">${dateUtils.formatDateTime(log.created_at || new Date())}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    // Update audit logs table (limit to 10 latest, use correct fields)
    updateAuditLogsTable(logs) {
        const tbody = domUtils.getElement('audit-logs-table');
        if (!tbody) return;

        tbody.innerHTML = '';

        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-2 text-center text-gray-400">No audit logs available</td></tr>';
            return;
        }

        logs.slice(0, 10).forEach(log => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-800';
            tr.innerHTML = `
                <td class="py-2 text-green-400">${log.id || 'N/A'}</td>
                <td class="py-2 text-blue-400">${log.action || 'N/A'}</td>
                <td class="py-2">${log.resource || 'N/A'}</td>
                <td class="py-2">${dateUtils.formatDateTime(log.timestamp || new Date())}</td>
                <td class="py-2 text-gray-400 text-xs">${log.details ? (typeof log.details === 'object' ? JSON.stringify(log.details) : log.details) : ''}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    // Load simulations data
    async loadSimulationsData() {
        try {
            const simulations = await apiClient.getAttackSimulations();
            if (simulations && simulations.simulations) {
                this.updateSimulationHistoryTable(simulations.simulations);
            }
        } catch (error) {
            console.error('Error loading simulations data:', error);
        }
    }

    // Update simulation history table
    updateSimulationHistoryTable(simulations) {
        const table = domUtils.getElement('simulation-history-table');
        if (!table) return;
        
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (!simulations || simulations.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-2 text-center text-gray-400">No simulations run yet</td></tr>';
            return;
        }
        
        simulations.forEach(sim => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-800';
            
            const statusClass = sim.status === 'COMPLETED' ? 'text-green-400' : 'text-yellow-400';
            
            tr.innerHTML = `
                <td class="py-2 text-green-400">${sim.id || 'N/A'}</td>
                <td class="py-2 text-red-400">${sim.attack_type || 'N/A'}</td>
                <td class="py-2">${sim.description || 'N/A'}</td>
                <td class="py-2 ${statusClass}">${sim.status || 'PENDING'}</td>
                <td class="py-2">${dateUtils.formatDateTime(sim.created_at || new Date())}</td>
            `;
            
            tbody.appendChild(tr);
        });
    }

    // =========================
    // Crypto Demo Event Listeners
    // =========================
    setupCryptoDemoEventListeners() {
        // AES encryption demo
        const aesEncryptBtn = domUtils.getElement('aes-encrypt-btn');
        const aesDecryptBtn = domUtils.getElement('aes-decrypt-btn');
        if (aesEncryptBtn) {
            aesEncryptBtn.addEventListener('click', () => this.handleAesEncrypt());
        }
        if (aesDecryptBtn) {
            aesDecryptBtn.addEventListener('click', () => this.handleAesDecrypt());
        }
        
        // RSA signature demo
        const rsaSignBtn = domUtils.getElement('rsa-sign-btn');
        const rsaVerifyBtn = domUtils.getElement('rsa-verify-btn');
        if (rsaSignBtn) {
            rsaSignBtn.addEventListener('click', () => this.handleRsaSign());
        }
        if (rsaVerifyBtn) {
            rsaVerifyBtn.addEventListener('click', () => this.handleRsaVerify());
        }
        
        // Merkle demo
        const generateMerkleBtn = domUtils.getElement('generate-merkle-btn');
        if (generateMerkleBtn) {
            generateMerkleBtn.addEventListener('click', () => this.handleGenerateMerkle());
        }
        
        // Homomorphic demo
        const homEncryptBtn = domUtils.getElement('hom-encrypt-btn');
        const homAddBtn = domUtils.getElement('hom-add-btn');
        const homDecryptBtn = domUtils.getElement('hom-decrypt-btn');
        if (homEncryptBtn) {
            homEncryptBtn.addEventListener('click', () => this.handleHomEncrypt());
        }
        if (homAddBtn) {
            homAddBtn.addEventListener('click', () => this.handleHomAdd());
        }
        if (homDecryptBtn) {
            homDecryptBtn.addEventListener('click', () => this.handleHomDecrypt());
        }
    }

    // Handle AES encryption demo
    async handleAesEncrypt() {
        const plaintext = document.getElementById('aes-plaintext')?.value;
        if (!plaintext) {
            this.toast.show('Please enter text to encrypt', 'danger');
            return;
        }
        
        try {
            const result = await apiClient.encryptData({ data: plaintext, timestamp: Date.now() });
            const output = document.getElementById('aes-encrypted-output');
            if (output && result.encrypted_data) {
                output.textContent = result.encrypted_data.ciphertext.substring(0, 100) + '...';
                output.dataset.fullCiphertext = result.encrypted_data.ciphertext;
                output.dataset.nonce = result.encrypted_data.nonce;
                output.dataset.tag = result.encrypted_data.tag;
            }
            this.toast.show('Data encrypted successfully', 'success');
        } catch (error) {
            console.error('AES encryption error:', error);
            this.toast.show('Encryption failed: ' + error.message, 'danger');
        }
    }

    // Handle AES decryption demo
    async handleAesDecrypt() {
        const output = document.getElementById('aes-encrypted-output');
        if (!output || !output.dataset.fullCiphertext) {
            this.toast.show('No encrypted data to decrypt', 'danger');
            return;
        }
        
        try {
            const result = await apiClient.decryptData({
                ciphertext: output.dataset.fullCiphertext,
                nonce: output.dataset.nonce,
                tag: output.dataset.tag
            });
            
            const plaintextField = document.getElementById('aes-plaintext');
            if (plaintextField && result.decrypted_data) {
                plaintextField.value = typeof result.decrypted_data === 'object' 
                    ? JSON.stringify(result.decrypted_data, null, 2) 
                    : result.decrypted_data;
            }
            this.toast.show('Data decrypted successfully', 'success');
        } catch (error) {
            console.error('AES decryption error:', error);
            this.toast.show('Decryption failed: ' + error.message, 'danger');
        }
    }

    // Handle RSA signature demo
    async handleRsaSign() {
        const data = document.getElementById('rsa-data')?.value;
        if (!data) {
            this.toast.show('Please enter data to sign', 'danger');
            return;
        }
        
        try {
            const result = await apiClient.signData({ data: data, timestamp: Date.now() });
            const output = document.getElementById('rsa-signature-output');
            if (output && result.signature) {
                output.textContent = result.signature.substring(0, 100) + '...';
                output.dataset.fullSignature = result.signature;
            }
            this.toast.show('Data signed successfully', 'success');
        } catch (error) {
            console.error('RSA signing error:', error);
            this.toast.show('Signing failed: ' + error.message, 'danger');
        }
    }

    // Handle RSA verification demo
    async handleRsaVerify() {
        const data = document.getElementById('rsa-data')?.value;
        const output = document.getElementById('rsa-signature-output');
        
        if (!data) {
            this.toast.show('Please enter data to verify', 'danger');
            return;
        }
        
        if (!output || !output.dataset.fullSignature) {
            this.toast.show('No signature to verify', 'danger');
            return;
        }
        
        try {
            const result = await apiClient.verifySignature(
                { data: data, timestamp: Date.now() }, 
                output.dataset.fullSignature
            );
            
            const isValid = result.valid || result.is_valid;
            this.toast.show(
                `Signature verification: ${isValid ? 'VALID' : 'INVALID'}`, 
                isValid ? 'success' : 'danger'
            );
        } catch (error) {
            console.error('RSA verification error:', error);
            this.toast.show('Verification failed: ' + error.message, 'danger');
        }
    }

    // Handle Merkle root generation demo
    async handleGenerateMerkle() {
        const transactionData = document.getElementById('merkle-transaction-data')?.value;
        if (!transactionData) {
            this.toast.show('Please enter transaction data', 'danger');
            return;
        }
        
        try {
            const leaves = [transactionData, cryptoUtils.generateRandomHex(32), cryptoUtils.generateRandomHex(32)];
            const result = await apiClient.createMerkleRoot(leaves);
            
            const output = document.getElementById('merkle-root-output');
            if (output && result.merkle_root) {
                output.textContent = result.merkle_root;
            }
            this.toast.show('Merkle root generated successfully', 'success');
        } catch (error) {
            console.error('Merkle root generation error:', error);
            this.toast.show('Merkle generation failed: ' + error.message, 'danger');
        }
    }

    // Handle homomorphic encryption demo
    handleHomEncrypt() {
        const val1 = document.getElementById('hom-value1')?.value;
        const val2 = document.getElementById('hom-value2')?.value;
        
        if (!val1 || !val2) {
            this.toast.show('Please enter both values', 'danger');
            return;
        }
        
        const output = document.getElementById('hom-encrypted-sum');
        if (output) {
            output.textContent = `Values encrypted: ${val1}, ${val2} (simulated)`;
        }
        this.toast.show('Homomorphic encryption simulated', 'success');
    }

    // Handle homomorphic addition demo
    handleHomAdd() {
        const val1 = parseInt(document.getElementById('hom-value1')?.value || '0');
        const val2 = parseInt(document.getElementById('hom-value2')?.value || '0');
        const sum = val1 + val2;
        
        const output = document.getElementById('hom-encrypted-sum');
        if (output) {
            output.textContent = `Encrypted sum represents: ${sum}`;
        }
        this.toast.show('Homomorphic addition completed', 'success');
    }

    // Handle homomorphic decryption demo
    handleHomDecrypt() {
        const output = document.getElementById('hom-encrypted-sum');
        if (output && output.textContent.includes('represents:')) {
            this.toast.show('Homomorphic decryption simulated', 'success');
        } else {
            this.toast.show('No encrypted sum to decrypt', 'danger');
        }
    }

    // =========================
    // Logs Tab Event Listeners
    // =========================
    setupLogsTabListeners() {
        const userLogsTab = domUtils.getElement('user-logs-tab');
        const securityLogsTab = domUtils.getElement('security-logs-tab');
        const auditLogsTab = domUtils.getElement('audit-logs-tab');

        if (userLogsTab) {
            userLogsTab.addEventListener('click', () => this.switchLogsTab('user-logs'));
        }
        if (securityLogsTab) {
            securityLogsTab.addEventListener('click', () => this.switchLogsTab('security-logs'));
        }
        if (auditLogsTab) {
            auditLogsTab.addEventListener('click', () => this.switchLogsTab('audit-logs'));
        }

        // Show only user logs by default
        this.switchLogsTab('user-logs');
    }

    // Switch logs tabs (show only selected section)
    switchLogsTab(tabName) {
        const userLogsTab = domUtils.getElement('user-logs-tab');
        const securityLogsTab = domUtils.getElement('security-logs-tab');
        const auditLogsTab = domUtils.getElement('audit-logs-tab');

        const activeClass = 'px-4 py-2 bg-green-500 text-black rounded-md';
        const inactiveClass = 'px-4 py-2 bg-gray-700 text-green-400 rounded-md';

        if (userLogsTab) userLogsTab.className = tabName === 'user-logs' ? activeClass : inactiveClass;
        if (securityLogsTab) securityLogsTab.className = tabName === 'security-logs' ? activeClass : inactiveClass;
        if (auditLogsTab) auditLogsTab.className = tabName === 'audit-logs' ? activeClass : inactiveClass;

        // Show/hide log tables
        const userLogsSection = domUtils.getElement('user-logs-table')?.closest('.bg-gray-900');
        const securityLogsSection = domUtils.getElement('security-logs-table')?.closest('.bg-gray-900');
        const auditLogsSection = domUtils.getElement('audit-logs-table')?.closest('.bg-gray-900');

        if (userLogsSection) userLogsSection.style.display = tabName === 'user-logs' ? '' : 'none';
        if (securityLogsSection) securityLogsSection.style.display = tabName === 'security-logs' ? '' : 'none';
        if (auditLogsSection) auditLogsSection.style.display = tabName === 'audit-logs' ? '' : 'none';

        // Load data for the specific tab
        switch(tabName) {
            case 'user-logs':
                this.loadUserLogs();
                break;
            case 'security-logs':
                this.loadSecurityLogs();
                break;
            case 'audit-logs':
                this.loadAuditLogs();
                break;
        }
    }

    // Load user logs tab data
    async loadUserLogs() {
        try {
            const logs = await apiClient.getUserActivityLogs();
            if (logs && logs.logs) {
                this.updateUserLogsTable(logs.logs);
            }
        } catch (error) {
            console.error('Error loading user logs:', error);
        }
    }

    // Load security logs tab data
    async loadSecurityLogs() {
        try {
            const logs = await apiClient.getSecurityEvents();
            if (logs && logs.events) {
                this.updateSecurityEvents(logs.events);
            }
        } catch (error) {
            console.error('Error loading security logs:', error);
        }
    }

    // Load audit logs tab data
    async loadAuditLogs() {
        try {
            const logs = await apiClient.getAuditLog();
            if (logs && logs.audit_log) {
                // Update audit log display (similar implementation)
                console.log('Audit logs loaded:', logs.audit_log.length);
            }
        } catch (error) {
            console.error('Error loading audit logs:', error);
        }
    }

    // =========================
    // Security Simulation Handlers
    // =========================
    // Red vs Blue Battle Statistics
    battleStats = {
        red: { sql: 0, brute: 0, mitm: 0, successful: 0, total: 0 },
        blue: { detected: 0, blocked: 0, blacklisted: 0 }
    };

    // Handle SQL Injection simulation button
    async handleSqlInjectionSim() {
        try {
            uiUtils.showLoading();
            this.addBattleLog('🔴 RED_TEAM: Launching SQL injection attack...', 'red');
            
            const result = await apiClient.simulateSqlInjection();
            
            // Update Red Team stats
            this.battleStats.red.sql++;
            this.battleStats.red.total++;
            
            // Check if attack was blocked
            const blocked = result.success === false || result.blocked === true;
            if (blocked) {
                this.battleStats.blue.detected++;
                this.battleStats.blue.blocked++;
                this.addBattleLog('🔵 BLUE_TEAM: SQL injection detected and blocked!', 'blue');
                this.addBattleLog('🛡️ DEFENSE: Attack signature matched in IDS', 'green');
            } else {
                this.battleStats.red.successful++;
                this.addBattleLog('⚠️ ALERT: SQL injection executed', 'yellow');
            }
            
            this.updateBattleVisuals();
            this.toast.show('SQL Injection simulation completed', blocked ? 'success' : 'warning');
            this.updateSimulationOutput('SQL Injection Simulation', result);
            await this.loadSimulationsData();
        } catch (error) {
            console.error('SQL Injection simulation error:', error);
            this.toast.show('Simulation failed: ' + error.message, 'danger');
            this.addBattleLog('❌ ERROR: Simulation failed - ' + error.message, 'error');
        } finally {
            uiUtils.hideLoading();
        }
    }

    // Handle Brute Force simulation button
    async handleBruteForceSim() {
        try {
            uiUtils.showLoading();
            this.addBattleLog('🔴 RED_TEAM: Initiating brute force attack...', 'red');
            
            const result = await apiClient.simulateBruteForce();
            
            // Update Red Team stats
            this.battleStats.red.brute++;
            this.battleStats.red.total++;
            
            // Check if attack was blocked
            const blocked = result.success === false || result.blocked === true;
            if (blocked) {
                this.battleStats.blue.detected++;
                this.battleStats.blue.blocked++;
                this.battleStats.blue.blacklisted++;
                this.addBattleLog('🔵 BLUE_TEAM: Brute force detected! IP blacklisted', 'blue');
                this.addBattleLog('🛡️ DEFENSE: Rate limiting activated', 'green');
            } else {
                this.battleStats.red.successful++;
                this.addBattleLog('⚠️ ALERT: Brute force in progress', 'yellow');
            }
            
            this.updateBattleVisuals();
            this.toast.show('Brute Force simulation completed', blocked ? 'success' : 'warning');
            this.updateSimulationOutput('Brute Force Simulation', result);
            await this.loadSimulationsData();
        } catch (error) {
            console.error('Brute Force simulation error:', error);
            this.toast.show('Simulation failed: ' + error.message, 'danger');
            this.addBattleLog('❌ ERROR: Simulation failed - ' + error.message, 'error');
        } finally {
            uiUtils.hideLoading();
        }
    }

    // Handle Replay Attack simulation button
    async handleReplayAttackSim() {
        try {
            uiUtils.showLoading();
            this.addBattleLog('🔴 RED_TEAM: Executing replay attack...', 'red');
            
            const result = await apiClient.simulateReplay();
            
            // Update Red Team stats
            this.battleStats.red.mitm++;
            this.battleStats.red.total++;
            
            // Check if attack was blocked
            const blocked = result.success === false || result.blocked === true;
            if (blocked) {
                this.battleStats.blue.detected++;
                this.battleStats.blue.blocked++;
                this.addBattleLog('🔵 BLUE_TEAM: Replay attack detected via nonce validation', 'blue');
                this.addBattleLog('🛡️ DEFENSE: Timestamp verification successful', 'green');
            } else {
                this.battleStats.red.successful++;
                this.addBattleLog('⚠️ ALERT: Replay attack succeeded', 'yellow');
            }
            
            this.updateBattleVisuals();
            this.toast.show('Replay Attack simulation completed', blocked ? 'success' : 'warning');
            this.updateSimulationOutput('Replay Attack Simulation', result);
            await this.loadSimulationsData();
        } catch (error) {
            console.error('Replay Attack simulation error:', error);
            this.toast.show('Simulation failed: ' + error.message, 'danger');
            this.addBattleLog('❌ ERROR: Simulation failed - ' + error.message, 'error');
        } finally {
            uiUtils.hideLoading();
        }
    }

    // Handle MITM Attack simulation button
    async handleMitmAttackSim() {
        try {
            uiUtils.showLoading();
            this.addBattleLog('🔴 RED_TEAM: Attempting Man-in-the-Middle attack...', 'red');
            
            const result = await apiClient.simulateMitm();
            
            // Update Red Team stats
            this.battleStats.red.mitm++;
            this.battleStats.red.total++;
            
            // Check if attack was blocked
            const blocked = result.success === false || result.blocked === true;
            if (blocked) {
                this.battleStats.blue.detected++;
                this.battleStats.blue.blocked++;
                this.addBattleLog('🔵 BLUE_TEAM: MITM attack thwarted by encryption', 'blue');
                this.addBattleLog('🛡️ DEFENSE: AES-256-GCM encryption verified', 'green');
            } else {
                this.battleStats.red.successful++;
                this.addBattleLog('⚠️ ALERT: MITM attack in progress', 'yellow');
            }
            
            this.updateBattleVisuals();
            this.toast.show('MITM Attack simulation completed', blocked ? 'success' : 'warning');
            this.updateSimulationOutput('MITM Attack Simulation', result);
            await this.loadSimulationsData();
        } catch (error) {
            console.error('MITM Attack simulation error:', error);
            this.toast.show('Simulation failed: ' + error.message, 'danger');
            this.addBattleLog('❌ ERROR: Simulation failed - ' + error.message, 'error');
        } finally {
            uiUtils.hideLoading();
        }
    }

    // Add log entry to battle log
    addBattleLog(message, type = 'info') {
        const battleLog = domUtils.getElement('battle-log');
        if (!battleLog) return;
        
        const logEntry = document.createElement('div');
        const timestamp = new Date().toLocaleTimeString();
        
        const colorClass = {
            'red': 'text-red-400',
            'blue': 'text-blue-400',
            'green': 'text-green-400',
            'yellow': 'text-yellow-400',
            'error': 'text-red-500',
            'info': 'text-gray-400'
        }[type] || 'text-gray-400';
        
        logEntry.className = colorClass;
        logEntry.textContent = `[${timestamp}] ${message}`;
        
        battleLog.appendChild(logEntry);
        battleLog.scrollTop = battleLog.scrollHeight;
        
        // Keep only last 100 entries
        while (battleLog.children.length > 100) {
            battleLog.removeChild(battleLog.firstChild);
        }
    }

    // Update battle visual statistics
    updateBattleVisuals() {
        const { red, blue } = this.battleStats;
        
        // Update Red Team counters
        const sqlAttempts = domUtils.getElement('red-sql-attempts');
        const bruteAttempts = domUtils.getElement('red-brute-attempts');
        const mitmAttempts = domUtils.getElement('red-mitm-attempts');
        const redSuccessRate = domUtils.getElement('red-success-rate');
        
        if (sqlAttempts) sqlAttempts.textContent = red.sql;
        if (bruteAttempts) bruteAttempts.textContent = red.brute;
        if (mitmAttempts) mitmAttempts.textContent = red.mitm;
        
        // Calculate and update Red Team success rate
        const redRate = red.total > 0 ? Math.round((red.successful / red.total) * 100) : 0;
        if (redSuccessRate) redSuccessRate.textContent = redRate + '%';
        
        // Update Red Team progress bars
        const maxAttempts = Math.max(red.sql, red.brute, red.mitm, 1);
        this.updateProgressBar('red-sql-bar', (red.sql / maxAttempts) * 100);
        this.updateProgressBar('red-brute-bar', (red.brute / maxAttempts) * 100);
        this.updateProgressBar('red-mitm-bar', (red.mitm / maxAttempts) * 100);
        
        // Update Blue Team counters
        const blueDetected = domUtils.getElement('blue-detected');
        const blueBlocked = domUtils.getElement('blue-blocked');
        const blueBlacklisted = domUtils.getElement('blue-blacklisted');
        const blueDefenseRate = domUtils.getElement('blue-defense-rate');
        
        if (blueDetected) blueDetected.textContent = blue.detected;
        if (blueBlocked) blueBlocked.textContent = blue.blocked;
        if (blueBlacklisted) blueBlacklisted.textContent = blue.blacklisted;
        
        // Calculate and update Blue Team defense rate
        const blueRate = red.total > 0 ? Math.round((blue.blocked / red.total) * 100) : 100;
        if (blueDefenseRate) {
            blueDefenseRate.textContent = blueRate + '%';
            blueDefenseRate.className = blueRate >= 80 ? 'text-2xl font-bold text-green-400' : 
                                         blueRate >= 50 ? 'text-2xl font-bold text-yellow-400' : 
                                         'text-2xl font-bold text-red-400';
        }
        
        // Update Blue Team progress bars
        const maxDefense = Math.max(blue.detected, blue.blocked, blue.blacklisted, 1);
        this.updateProgressBar('blue-detected-bar', (blue.detected / maxDefense) * 100);
        this.updateProgressBar('blue-blocked-bar', (blue.blocked / maxDefense) * 100);
        this.updateProgressBar('blue-blacklist-bar', (blue.blacklisted / maxDefense) * 100);
        
        // Update battle status
        const battleStatus = domUtils.getElement('battle-status');
        if (battleStatus) {
            const statusText = blueRate >= 80 ? '<span class="text-green-400">System Secure</span>' :
                               blueRate >= 50 ? '<span class="text-yellow-400">Under Attack</span>' :
                               '<span class="text-red-400">Critical Threat</span>';
            battleStatus.innerHTML = `Status: ${statusText}`;
        }
    }

    // Update progress bar width
    updateProgressBar(barId, percentage) {
        const bar = domUtils.getElement(barId);
        if (bar) {
            bar.style.width = Math.min(percentage, 100) + '%';
        }
    }

    // Update simulation output display
    updateSimulationOutput(title, result) {
        const output = domUtils.getElement('simulation-output');
        if (!output) return;
        
        output.innerHTML = `<div class="text-green-400 mb-2">${title}</div>`;
        
        if (result && result.phases) {
            result.phases.forEach((phase, index) => {
                const phaseDiv = document.createElement('div');
                const bgClass = phase.description.includes('defense') ? 'bg-blue-900/30 text-blue-400' :
                    phase.description.includes('attack') ? 'bg-red-900/30 text-red-400' :
                    'bg-green-900/30 text-green-400';
                    
                phaseDiv.className = `mb-2 p-2 rounded ${bgClass}`;
                phaseDiv.textContent = `[Phase ${index+1}] ${phase.description}`;
                output.appendChild(phaseDiv);
            });
        } else if (result && result.message) {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'text-gray-400 p-2';
            messageDiv.textContent = result.message;
            output.appendChild(messageDiv);
        }
        
        output.scrollTop = output.scrollHeight;
    }

    // =========================
    // Real-Time Updates & Cleanup
    // =========================
    // Start real-time updates
    startRealTimeUpdates() {
        // Update dashboard every 30 seconds
        const dashboardInterval = setInterval(() => {
            if (this.currentView === 'dashboard' && this.isLoggedIn) {
                this.loadDashboardData();
            }
        }, 30000);
        
        this.updateIntervals.set('dashboard', dashboardInterval);
    }

    // Stop real-time updates
    stopRealTimeUpdates() {
        for (const [key, interval] of this.updateIntervals) {
            clearInterval(interval);
        }
        this.updateIntervals.clear();
        
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }

    // Clean up resources when app is destroyed
    cleanup() {
        this.stopRealTimeUpdates();
        
        // Destroy charts
        for (const [id, chart] of this.charts) {
            if (chart && chart.destroy) {
                chart.destroy();
            }
        }
        this.charts.clear();
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', async () => {
    window.app = new SecureTradingApp();
    await window.app.init();
});

// Handle page unload
window.addEventListener('beforeunload', () => {
    if (window.app) {
        window.app.cleanup();
    }
});

// Export the app instance for global access
export default window.app;