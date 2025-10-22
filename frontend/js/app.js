/**
 * Main Application File for Secure Trading Platform
 * Fixed version with proper error handling and data flow
 */

// Import required modules
import { apiClient } from '/static/api/apiService.js';
import { domUtils, formUtils, dateUtils, numberUtils, uiUtils, validationRules, eventUtils, cryptoUtils } from '/static/js/utils.js';
import { TableComponent, CardComponent, ChartComponent, ModalComponent, FormComponent, TabComponent, ToastComponent, ProgressBarComponent, ListComponent } from '/static/js/components.js';

// Main application class
class SecureTradingApp {
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

    // Initialize the application
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

    // Set up DOM elements
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

    // Set up event listeners
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

    // Check authentication status on page load
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

    // Handle login
    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        
        if (!username || !password) {
            this.toast.show('Please enter username and password', 'danger');
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

    // Handle registration
    async handleRegister(e) {
        e.preventDefault();
        
        const username = document.getElementById('register-username').value;
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;
        
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

    // Handle logout
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

    // Handle order placement
    async handleOrder(e) {
        e.preventDefault();
        
        const symbol = document.getElementById('order-asset').value;
        const side = document.getElementById('order-type').value;
        const quantity = parseFloat(document.getElementById('order-amount').value);
        const price = parseFloat(document.getElementById('order-price').value);
        
        if (!symbol || !side || !quantity || !price) {
            this.toast.show('Please fill all order fields', 'danger');
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

    // Handle trading order placement
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
                this.toast.show(`Order placed successfully for ${quantity} ${symbol}`, 'success');
                await this.loadTradingData();
                document.getElementById('trading-order-form').reset();
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

    // Handle navigation between views
    handleNavigation(e) {
        e.preventDefault();
        const target = e.target.closest('a');
        if (!target) return;
        
        const view = target.getAttribute('href').substring(1);
        this.switchView(view);
    }

    // Switch between views
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

    // Load view-specific data
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

    // Show authentication view
    showAuthView() {
        if (this.elements.mainView) domUtils.hide(this.elements.mainView);
        if (this.elements.authView) domUtils.show(this.elements.authView);
    }

    // Show main application view
    showMainView() {
        if (this.elements.authView) domUtils.hide(this.elements.authView);
        if (this.elements.mainView) domUtils.show(this.elements.mainView);
    }

    // Show login tab
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

    // Show register tab
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

    // Initialize all views
    async initializeViews() {
        await this.loadAssets();
    }

    // Load assets for order forms
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

    // Load dashboard data
    async loadDashboardData() {
        try {
            const [marketData, orders, securityEvents, portfolio] = await Promise.allSettled([
                apiClient.getMarketOverview(),
                apiClient.getUserOrders(),
                apiClient.getSecurityEvents(),
                apiClient.getUserPortfolio(this.userId)
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
            
            // Update system status
            this.updateSystemStatus();
        } catch (error) {
            console.error('Error loading dashboard data:', error);
        }
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

    // Update system status
    updateSystemStatus() {
        const dashboardMerkleRoot = domUtils.getElement('dashboard-merkle-root');
        if (dashboardMerkleRoot) {
            dashboardMerkleRoot.textContent = cryptoUtils.generateRandomHex(16) + '...';
        }
    }

    // Load recent orders
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

    // Load trading data
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

    // Update portfolio table
    updatePortfolioTable(portfolio) {
        const table = domUtils.getElement('portfolio-table');
        if (!table) return;
        
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (!portfolio.assets || portfolio.assets.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-2 text-center text-gray-400">No assets in portfolio</td></tr>';
            return;
        }
        
        portfolio.assets.forEach(asset => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-800';
            
            const change = asset.change || 0;
            const changeClass = change >= 0 ? 'text-green-400' : 'text-red-400';
            const changePrefix = change >= 0 ? '+' : '';
            
            tr.innerHTML = `
                <td class="py-2 text-green-400">${asset.symbol || 'N/A'}</td>
                <td class="py-2 text-right">${numberUtils.formatNumber(asset.quantity || 0, 4)}</td>
                <td class="py-2 text-right">${numberUtils.formatCurrency(asset.price || 0, 2)}</td>
                <td class="py-2 text-right">${numberUtils.formatCurrency(asset.total_value || 0, 2)}</td>
                <td class="py-2 text-right ${changeClass}">${changePrefix}${numberUtils.formatPercentage(change, 2)}</td>
            `;
            
            tbody.appendChild(tr);
        });
    }

    // Load security data
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

    // Unblock IP
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

    // Load crypto data
    async loadCryptoData() {
        // Crypto demos are client-side only
        console.log('Crypto demo view loaded');
    }

    // Load logs data
    async loadLogsData() {
        try {
            const userLogs = await apiClient.getUserActivityLogs();
            if (userLogs && userLogs.logs) {
                this.updateUserLogsTable(userLogs.logs);
            }
        } catch (error) {
            console.error('Error loading logs data:', error);
        }
    }

    // Update user logs table
    updateUserLogsTable(logs) {
        const tbody = domUtils.getElement('user-logs-table');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="py-2 text-center text-gray-400">No logs available</td></tr>';
            return;
        }
        
        logs.forEach(log => {
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

    // Setup crypto demo event listeners
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

    // Handle Merkle root generation
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

    // Setup logs tab listeners
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
    }

    // Switch logs tabs
    switchLogsTab(tabName) {
        const userLogsTab = domUtils.getElement('user-logs-tab');
        const securityLogsTab = domUtils.getElement('security-logs-tab');
        const auditLogsTab = domUtils.getElement('audit-logs-tab');
        
        const activeClass = 'px-4 py-2 bg-green-500 text-black rounded-md';
        const inactiveClass = 'px-4 py-2 bg-gray-700 text-green-400 rounded-md';
        
        if (userLogsTab) userLogsTab.className = tabName === 'user-logs' ? activeClass : inactiveClass;
        if (securityLogsTab) securityLogsTab.className = tabName === 'security-logs' ? activeClass : inactiveClass;
        if (auditLogsTab) auditLogsTab.className = tabName === 'audit-logs' ? activeClass : inactiveClass;
        
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

    // Load specific log types
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

    // Handle simulation buttons
    async handleSqlInjectionSim() {
        try {
            uiUtils.showLoading();
            const result = await apiClient.simulateSqlInjection();
            this.toast.show('SQL Injection simulation completed', 'success');
            this.updateSimulationOutput('SQL Injection Simulation', result);
            await this.loadSimulationsData();
        } catch (error) {
            console.error('SQL Injection simulation error:', error);
            this.toast.show('Simulation failed: ' + error.message, 'danger');
        } finally {
            uiUtils.hideLoading();
        }
    }

    async handleBruteForceSim() {
        try {
            uiUtils.showLoading();
            const result = await apiClient.simulateBruteForce();
            this.toast.show('Brute Force simulation completed', 'success');
            this.updateSimulationOutput('Brute Force Simulation', result);
            await this.loadSimulationsData();
        } catch (error) {
            console.error('Brute Force simulation error:', error);
            this.toast.show('Simulation failed: ' + error.message, 'danger');
        } finally {
            uiUtils.hideLoading();
        }
    }

    async handleReplayAttackSim() {
        try {
            uiUtils.showLoading();
            const result = await apiClient.simulateReplay();
            this.toast.show('Replay Attack simulation completed', 'success');
            this.updateSimulationOutput('Replay Attack Simulation', result);
            await this.loadSimulationsData();
        } catch (error) {
            console.error('Replay Attack simulation error:', error);
            this.toast.show('Simulation failed: ' + error.message, 'danger');
        } finally {
            uiUtils.hideLoading();
        }
    }

    async handleMitmAttackSim() {
        try {
            uiUtils.showLoading();
            const result = await apiClient.simulateMitm();
            this.toast.show('MITM Attack simulation completed', 'success');
            this.updateSimulationOutput('MITM Attack Simulation', result);
            await this.loadSimulationsData();
        } catch (error) {
            console.error('MITM Attack simulation error:', error);
            this.toast.show('Simulation failed: ' + error.message, 'danger');
        } finally {
            uiUtils.hideLoading();
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