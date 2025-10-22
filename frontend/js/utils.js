/**
 * Utility Functions for Secure Trading Platform
 * Contains common utility functions for the application
 */

// DOM utilities
export const domUtils = {
    // Get DOM element by ID
    getElement: (id) => document.getElementById(id),
    
    // Get DOM element by selector
    query: (selector) => document.querySelector(selector),
    
    // Get all DOM elements by selector
    queryAll: (selector) => document.querySelectorAll(selector),
    
    // Create DOM element with class and text
    createElement: (tag, className = '', text = '') => {
        const element = document.createElement(tag);
        if (className) element.className = className;
        if (text) element.textContent = text;
        return element;
    },
    
    // Toggle class on element
    toggleClass: (element, className) => {
        if (element) element.classList.toggle(className);
    },
    
    // Add one or more classes to element
    addClass: (element, ...classNames) => {
        if (!element) return;
        const allClasses = classNames
            .filter(name => typeof name === 'string')
            .flatMap(name => name.split(' '))
            .filter(c => c.length > 0);
        try {
            element.classList.add(...allClasses);
        } catch (error) {
            // Fallback to adding one by one if bulk add fails
            allClasses.forEach(cls => {
                try {
                    element.classList.add(cls);
                } catch (e) {
                    console.warn(`Failed to add class: ${cls}`, e);
                }
            });
        }
    },
    
    // Remove class from element
    removeClass: (element, className) => {
        if (element) element.classList.remove(className);
    },
    
    // Set element visibility
    setVisible: (element, visible) => {
        if (element) element.classList.toggle('hidden', !visible);
    },
    
    // Show element
    show: (element) => {
        if (element) domUtils.removeClass(element, 'hidden');
    },
    
    // Hide element
    hide: (element) => {
        if (element) domUtils.addClass(element, 'hidden');
    },
    
    // Fade out element
    fadeOut: (element, duration = 300) => {
        if (element) {
            element.style.transition = `opacity ${duration}ms`;
            element.style.opacity = '0';
            setTimeout(() => {
                domUtils.hide(element);
                element.style.opacity = '';
                element.style.transition = '';
            }, duration);
        }
    },
    
    // Fade in element
    fadeIn: (element, duration = 300) => {
        if (element) {
            domUtils.show(element);
            element.style.opacity = '0';
            element.style.transition = `opacity ${duration}ms`;
            // Trigger reflow
            void element.offsetWidth;
            element.style.opacity = '1';
            setTimeout(() => {
                element.style.opacity = '';
                element.style.transition = '';
            }, duration);
        }
    }
};

// Form utilities
export const formUtils = {
    // Validate form fields
    validateField: (element, rules) => {
        const value = element.value;
        const errors = [];
        
        if (rules.required && !value.trim()) {
            errors.push('This field is required');
        }
        
        if (rules.minLength && value.length < rules.minLength) {
            errors.push(`Minimum length is ${rules.minLength} characters`);
        }
        
        if (rules.maxLength && value.length > rules.maxLength) {
            errors.push(`Maximum length is ${rules.maxLength} characters`);
        }
        
        if (rules.pattern && !rules.pattern.test(value)) {
            errors.push(rules.patternMessage || 'Invalid format');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    },
    
    // Validate entire form
    validateForm: (form, validationRules) => {
        let isValid = true;
        const formErrors = {};
        
        for (const fieldName in validationRules) {
            const field = form.querySelector(`[name="${fieldName}"]`) || form.querySelector(`#${fieldName}`);
            if (field) {
                const result = formUtils.validateField(field, validationRules[fieldName]);
                if (!result.isValid) {
                    isValid = false;
                    formErrors[fieldName] = result.errors;
                }
            }
        }
        
        return {
            isValid,
            errors: formErrors
        };
    },
    
    // Show form errors
    showErrors: (formErrors) => {
        for (const fieldName in formErrors) {
            const field = document.querySelector(`[name="${fieldName}"]`) || document.querySelector(`#${fieldName}`);
            if (field) {
                field.classList.add('form-invalid');
                
                // Remove existing error messages
                const existingError = field.parentNode.querySelector('.error-message');
                if (existingError) existingError.remove();
                
                // Add error message
                const errorDiv = document.createElement('div');
                errorDiv.className = 'error-message text-red-400 text-xs mt-1';
                errorDiv.textContent = formErrors[fieldName][0];
                field.parentNode.appendChild(errorDiv);
            }
        }
    },
    
    // Clear form errors
    clearErrors: (form) => {
        const invalidFields = form.querySelectorAll('.form-invalid');
        invalidFields.forEach(field => field.classList.remove('form-invalid'));
        
        const errorMessages = form.querySelectorAll('.error-message');
        errorMessages.forEach(msg => msg.remove());
    },
    
    // Disable form
    disableForm: (form, disabled = true) => {
        const inputs = form.querySelectorAll('input, select, button');
        inputs.forEach(input => {
            input.disabled = disabled;
            if (disabled) {
                input.classList.add('cursor-not-allowed', 'pointer-events-none');
            } else {
                input.classList.remove('cursor-not-allowed', 'pointer-events-none');
            }
        });
    }
};

// Date utilities
export const dateUtils = {
    // Format date as YYYY-MM-DD HH:MM:SS
    formatDateTime: (date) => {
        if (!date) return '';
        const d = new Date(date);
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        const hours = String(d.getHours()).padStart(2, '0');
        const minutes = String(d.getMinutes()).padStart(2, '0');
        const seconds = String(d.getSeconds()).padStart(2, '0');
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    },
    
    // Format date as HH:MM:SS
    formatTime: (date) => {
        if (!date) return '';
        const d = new Date(date);
        const hours = String(d.getHours()).padStart(2, '0');
        const minutes = String(d.getMinutes()).padStart(2, '0');
        const seconds = String(d.getSeconds()).padStart(2, '0');
        return `${hours}:${minutes}:${seconds}`;
    },
    
    // Format relative time
    formatRelativeTime: (date) => {
        if (!date) return '';
        const now = new Date();
        const past = new Date(date);
        const diffInSeconds = Math.floor((now - past) / 1000);
        
        if (diffInSeconds < 60) return `${diffInSeconds}s ago`;
        if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
        if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
        return `${Math.floor(diffInSeconds / 86400)}d ago`;
    }
};

// Number utilities
export const numberUtils = {
    // Format number with commas
    formatNumber: (num) => {
        if (num === null || num === undefined) return '0';
        return Number(num).toLocaleString();
    },
    
    // Format currency
    formatCurrency: (num, decimals = 2) => {
        if (num === null || num === undefined) return '$0.00';
        return '$' + Number(num).toFixed(decimals).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },
    
    // Format percentage
    formatPercentage: (num, decimals = 2) => {
        if (num === null || num === undefined) return '0%';
        return Number(num).toFixed(decimals) + '%';
    },
    
    // Round to specified decimals
    round: (num, decimals = 2) => {
        if (num === null || num === undefined) return 0;
        const factor = Math.pow(10, decimals);
        return Math.round(num * factor) / factor;
    }
};

// String utilities
export const stringUtils = {
    // Truncate string
    truncate: (str, maxLength, suffix = '...') => {
        if (!str) return '';
        if (str.length <= maxLength) return str;
        return str.substr(0, maxLength - suffix.length) + suffix;
    },
    
    // Capitalize first letter
    capitalize: (str) => {
        if (!str) return '';
        return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
    },
    
    // Convert to title case
    toTitleCase: (str) => {
        if (!str) return '';
        return str.replace(/\w\S*/g, (txt) => 
            txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase()
        );
    }
};

// UI utilities
export const uiUtils = {
    // Show loading overlay
    showLoading: () => {
        const overlay = domUtils.getElement('loading-overlay');
        if (overlay) domUtils.show(overlay);
    },
    
    // Hide loading overlay
    hideLoading: () => {
        const overlay = domUtils.getElement('loading-overlay');
        if (overlay) domUtils.hide(overlay);
    },
    
    // Show message
    showMessage: (message, type = 'info') => {
        const messageArea = domUtils.getElement('message-area');
        if (!messageArea) return;
        
        messageArea.textContent = message;
        messageArea.className = `mb-4 text-center text-sm font-medium ${
            type === 'danger' ? 'text-red-400' :
            type === 'warning' ? 'text-yellow-400' :
            type === 'success' ? 'text-green-400' :
            'text-green-400'
        }`;
        
        // Clear message after 5 seconds
        setTimeout(() => {
            messageArea.textContent = '';
            messageArea.className = 'mb-4 text-center text-sm font-medium';
        }, 5000);
    },
    
    // Show security event in the dashboard
    addSecurityEvent: (type, description) => {
        const eventsContainer = domUtils.getElement('security-events-container');
        if (!eventsContainer) return;
        
        const timestamp = dateUtils.formatTime(new Date());
        
        const eventDiv = document.createElement('div');
        eventDiv.className = 'p-2 bg-gray-800 rounded';
        eventDiv.innerHTML = `
            <div class="flex justify-between">
                <span class="text-green-400">${type}</span>
                <span class="text-gray-500">${timestamp}</span>
            </div>
            <div class="text-gray-400">${description}</div>
        `;
        
        eventsContainer.insertBefore(eventDiv, eventsContainer.firstChild);
        
        // Keep only the last 10 events
        while (eventsContainer.children.length > 10) {
            eventsContainer.removeChild(eventsContainer.lastChild);
        }
    },
    
    // Update uptime display
    updateUptime: () => {
        const startDate = new Date();
        startDate.setHours(0, 0, 0, 0); // Start of day for demo
        
        setInterval(() => {
            const now = new Date();
            const diff = Math.floor((now - startDate) / 1000); // Difference in seconds
            const hours = Math.floor(diff / 3600);
            const minutes = Math.floor((diff % 3600) / 60);
            const seconds = diff % 60;
            
            const formattedTime = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            
            // Update dashboard uptime
            const dashboardUptime = domUtils.getElement('dashboard-uptime');
            if (dashboardUptime) dashboardUptime.textContent = formattedTime;
            
            // Update header uptime if it exists
            const headerUptime = domUtils.getElement('header-uptime');
            if (headerUptime) headerUptime.textContent = formattedTime;
        }, 1000);
    }
};

// Validation rules
export const validationRules = {
    username: {
        required: true,
        minLength: 3,
        maxLength: 30,
        pattern: /^[a-zA-Z0-9_]+$/,
        patternMessage: 'Username can only contain letters, numbers, and underscores'
    },
    password: {
        required: true,
        minLength: 6,
        maxLength: 128,
        pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{6,}$/,
        patternMessage: 'Password must contain at least one uppercase letter, one lowercase letter, and one number'
    },
    confirmPassword: {
        required: true
    },
    asset: {
        required: true
    },
    amount: {
        required: true,
        pattern: /^\d+(\.\d+)?$/,
        patternMessage: 'Amount must be a valid number'
    },
    price: {
        required: true,
        pattern: /^\d+(\.\d+)?$/,
        patternMessage: 'Price must be a valid number'
    }
};

// Event utilities
export const eventUtils = {
    // Debounce function
    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    // Throttle function
    throttle: (func, limit) => {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
};

// Crypto utilities
export const cryptoUtils = {
    // Generate random hex string
    generateRandomHex: (length) => {
        return Array.from({ length }, () => 
            Math.floor(Math.random() * 16).toString(16)
        ).join('');
    },
    
    // Format hash for display
    formatHash: (hash, start = 4, end = 4) => {
        if (!hash) return 'N/A';
        if (hash.length <= start + end) return hash;
        return hash.substring(0, start) + '...' + hash.substring(hash.length - end);
    }
};

// Initialize utilities on DOM content loaded
document.addEventListener('DOMContentLoaded', () => {
    // Start updating uptime
    uiUtils.updateUptime();
    
    // Set up any initial UI elements
    const systemStatus = domUtils.getElement('system-status');
    if (systemStatus) systemStatus.textContent = 'LIVE';
    
    // Set up live indicator
    const liveIndicator = document.querySelector('.live-indicator');
    if (liveIndicator) liveIndicator.classList.add('animate-pulse');
});