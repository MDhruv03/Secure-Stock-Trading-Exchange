/**
 * Component Module for Secure Trading Platform
 * Contains reusable UI components
 */

import { domUtils, numberUtils, dateUtils, stringUtils, cryptoUtils } from './utils.js';

// Table component
export class TableComponent {
    constructor(containerId) {
        this.container = domUtils.getElement(containerId);
        this.table = null;
    }

    // Initialize table with headers
    init(headers) {
        if (!this.container) return;
        
        this.table = domUtils.createElement('table', 'w-full text-sm');
        const thead = domUtils.createElement('thead');
        const headerRow = domUtils.createElement('tr', 'border-b border-gray-700');
        
        headers.forEach(header => {
            const th = domUtils.createElement('th', 'text-left text-gray-400 py-2');
            th.textContent = header.toUpperCase();
            headerRow.appendChild(th);
        });
        
        thead.appendChild(headerRow);
        this.table.appendChild(thead);
        
        const tbody = domUtils.createElement('tbody', 'text-gray-300');
        this.table.appendChild(tbody);
        
        this.container.innerHTML = '';
        this.container.appendChild(this.table);
        
        return this.table;
    }

    // Add data rows
    addRows(data, cellFormatter = null) {
        if (!this.table) return;
        
        const tbody = this.table.querySelector('tbody');
        tbody.innerHTML = '';
        
        if (!data || data.length === 0) {
            const emptyRow = domUtils.createElement('tr');
            const emptyCell = domUtils.createElement('td', 'py-4 text-center text-gray-500', 'No data available');
            emptyCell.setAttribute('colspan', this.table.querySelectorAll('th').length);
            emptyRow.appendChild(emptyCell);
            tbody.appendChild(emptyRow);
            return;
        }

        data.forEach(row => {
            const tr = domUtils.createElement('tr', 'border-b border-gray-800');
            
            Object.values(row).forEach((value, index) => {
                const td = domUtils.createElement('td', 'py-2');
                
                // Apply custom formatting if provided
                if (cellFormatter && cellFormatter[index]) {
                    td.innerHTML = cellFormatter[index](value, row);
                } else {
                    td.textContent = value !== null && value !== undefined ? value.toString() : '';
                }
                
                tr.appendChild(td);
            });
            
            tbody.appendChild(tr);
        });
    }
}

// Card component
export class CardComponent {
    constructor(containerId, title, icon = null) {
        this.container = domUtils.getElement(containerId);
        this.title = title;
        this.icon = icon;
        this.card = null;
    }

    // Initialize card
    init() {
        if (!this.container) return;
        
        this.card = domUtils.createElement('div', 'bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors duration-300');
        
        const header = domUtils.createElement('h3', 'text-lg font-semibold text-green-400 mb-4 flex items-center');
        if (this.icon) {
            const iconEl = domUtils.createElement('i', this.icon + ' mr-2');
            header.appendChild(iconEl);
        }
        header.textContent = this.title;
        
        this.card.appendChild(header);
        
        this.container.innerHTML = '';
        this.container.appendChild(this.card);
        
        return this;
    }

    // Add content to card
    addContent(content) {
        if (!this.card) return;
        
        // Accept either DOM element or string
        if (typeof content === 'string') {
            this.card.innerHTML += content;
        } else {
            this.card.appendChild(content);
        }
        
        return this;
    }

    // Update card data
    updateData(data) {
        if (!this.card) return;
        
        // Custom logic to update card based on data
        for (const key in data) {
            const element = this.card.querySelector(`[data-field="${key}"]`);
            if (element) {
                element.textContent = data[key];
            }
        }
    }
}

// Chart component
export class ChartComponent {
    constructor(containerId, type = 'line') {
        this.container = domUtils.getElement(containerId);
        this.type = type;
        this.chart = null;
        this.canvas = null;
    }

    // Initialize chart
    init(options = {}) {
        if (!this.container) return;
        
        // Remove existing canvas if present
        if (this.canvas) {
            this.canvas.remove();
        }
        
        this.canvas = domUtils.createElement('canvas');
        this.container.innerHTML = '';
        this.container.appendChild(this.canvas);
        
        // Create chart
        this.chart = new Chart(this.canvas, {
            type: this.type,
            data: options.data || { labels: [], datasets: [] },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        labels: {
                            color: '#e2e8f0'
                        }
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
                }
            }
        });
        
        return this;
    }

    // Update chart data
    updateData(data) {
        if (this.chart) {
            this.chart.data = data;
            this.chart.update();
        }
        return this;
    }

    // Update chart options
    updateOptions(options) {
        if (this.chart) {
            this.chart.options = { ...this.chart.options, ...options };
            this.chart.update();
        }
        return this;
    }
}

// Modal component
export class ModalComponent {
    constructor(id, title) {
        this.id = id;
        this.title = title;
        this.modal = null;
        this.body = null;
    }

    // Initialize modal
    init() {
        // Create modal elements
        this.modal = domUtils.createElement('div', 'modal');
        this.modal.id = this.id;
        
        const modalContent = domUtils.createElement('div', 'modal-content relative');
        
        // Header
        const header = domUtils.createElement('div', 'flex justify-between items-center mb-4');
        const title = domUtils.createElement('h2', 'text-xl font-bold text-green-400', this.title);
        const closeBtn = domUtils.createElement('button', 'text-gray-400 hover:text-white text-2xl');
        closeBtn.innerHTML = '&times;';
        closeBtn.onclick = () => this.close();
        
        header.appendChild(title);
        header.appendChild(closeBtn);
        
        // Body
        this.body = domUtils.createElement('div', 'modal-body');
        
        modalContent.appendChild(header);
        modalContent.appendChild(this.body);
        
        this.modal.appendChild(modalContent);
        
        // Add to document
        document.body.appendChild(this.modal);
        
        return this;
    }

    // Show modal
    show() {
        if (this.modal) {
            this.modal.classList.add('active');
            document.body.classList.add('overflow-hidden');
        }
        return this;
    }

    // Hide modal
    close() {
        if (this.modal) {
            this.modal.classList.remove('active');
            document.body.classList.remove('overflow-hidden');
        }
        return this;
    }

    // Set modal content
    setContent(content) {
        if (this.body) {
            this.body.innerHTML = '';
            if (typeof content === 'string') {
                this.body.innerHTML = content;
            } else {
                this.body.appendChild(content);
            }
        }
        return this;
    }
}

// Form component
export class FormComponent {
    constructor(containerId) {
        this.container = domUtils.getElement(containerId);
        this.form = null;
        this.fields = {};
    }

    // Initialize form
    init(config) {
        if (!this.container) return;
        
        this.form = domUtils.createElement('form', config.className || '');
        
        // Add form fields
        config.fields.forEach(fieldConfig => {
            const field = this.createField(fieldConfig);
            this.form.appendChild(field);
            this.fields[fieldConfig.name] = field;
        });
        
        // Add submit button if needed
        if (config.submitButton) {
            const submitBtn = domUtils.createElement('button', config.submitButton.className || 'w-full bg-green-500 hover:bg-green-400 text-black font-semibold py-2 px-4 rounded-md transition-all duration-200 transform hover:scale-105');
            submitBtn.type = 'submit';
            submitBtn.textContent = config.submitButton.text || '$ submit';
            this.form.appendChild(submitBtn);
        }
        
        this.container.innerHTML = '';
        this.container.appendChild(this.form);
        
        return this;
    }

    // Create form field
    createField(config) {
        const container = domUtils.createElement('div', config.containerClass || 'mb-4');
        
        // Label
        if (config.label) {
            const label = domUtils.createElement('label', config.labelClass || 'block text-xs text-gray-400 mb-1');
            label.textContent = config.label;
            container.appendChild(label);
        }
        
        // Field element
        let fieldEl;
        switch (config.type) {
            case 'select':
                fieldEl = domUtils.createElement('select', config.fieldClass || 'w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors');
                fieldEl.id = config.name;
                fieldEl.name = config.name;
                
                if (config.options) {
                    config.options.forEach(option => {
                        const opt = domUtils.createElement('option', '', option.text || option.value);
                        opt.value = option.value;
                        if (option.selected) opt.selected = true;
                        fieldEl.appendChild(opt);
                    });
                }
                break;
                
            case 'textarea':
                fieldEl = domUtils.createElement('textarea', config.fieldClass || 'w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors');
                fieldEl.id = config.name;
                fieldEl.name = config.name;
                fieldEl.rows = config.rows || 3;
                if (config.placeholder) fieldEl.placeholder = config.placeholder;
                break;
                
            default:
                fieldEl = domUtils.createElement('input', config.fieldClass || 'w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors');
                fieldEl.type = config.type || 'text';
                fieldEl.id = config.name;
                fieldEl.name = config.name;
                if (config.placeholder) fieldEl.placeholder = config.placeholder;
                if (config.step) fieldEl.step = config.step;
                if (config.required) fieldEl.required = config.required;
        }
        
        container.appendChild(fieldEl);
        return container;
    }

    // Set form values
    setValues(values) {
        for (const name in values) {
            const field = this.form.querySelector(`[name="${name}"]`);
            if (field) {
                if (field.type === 'select-one') {
                    field.value = values[name];
                } else {
                    field.value = values[name];
                }
            }
        }
        return this;
    }

    // Get form values
    getValues() {
        const values = {};
        const elements = this.form.querySelectorAll('input, select, textarea');
        elements.forEach(el => {
            values[el.name] = el.value;
        });
        return values;
    }

    // Validate form
    validate(rules) {
        let isValid = true;
        const errors = {};
        
        for (const fieldName in rules) {
            const field = this.form.querySelector(`[name="${fieldName}"]`);
            if (field) {
                // Simple validation based on rules
                if (rules[fieldName].required && !field.value.trim()) {
                    errors[fieldName] = 'This field is required';
                    isValid = false;
                }
                
                // Add other validation rules as needed
            }
        }
        
        return { isValid, errors };
    }
}

// Tab component
export class TabComponent {
    constructor(containerId, tabs) {
        this.container = domUtils.getElement(containerId);
        this.tabs = tabs;
        this.activeTab = tabs[0].id;
    }

    // Initialize tabs
    init() {
        if (!this.container) return;
        
        // Create tab list
        const tabList = domUtils.createElement('div', 'flex mb-4');
        
        this.tabs.forEach(tab => {
            const tabBtn = domUtils.createElement('button', 
                tab.id === this.activeTab 
                    ? 'px-4 py-2 bg-green-500 text-black rounded-md' 
                    : 'px-4 py-2 bg-gray-700 text-green-400 rounded-md hover:bg-gray-600'
            );
            tabBtn.textContent = tab.label;
            tabBtn.dataset.tab = tab.id;
            
            tabBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.switchTab(tab.id);
            });
            
            tabList.appendChild(tabBtn);
        });
        
        this.container.innerHTML = '';
        this.container.appendChild(tabList);
        
        // Hide all tab content initially, show active tab
        this.tabs.forEach(tab => {
            const content = domUtils.getElement(tab.contentId);
            if (content) {
                domUtils.setVisible(content, tab.id === this.activeTab);
            }
        });
        
        return this;
    }

    // Switch active tab
    switchTab(tabId) {
        // Update tab buttons
        const tabBtns = this.container.querySelectorAll('button[data-tab]');
        tabBtns.forEach(btn => {
            if (btn.dataset.tab === tabId) {
                btn.className = 'px-4 py-2 bg-green-500 text-black rounded-md';
            } else {
                btn.className = 'px-4 py-2 bg-gray-700 text-green-400 rounded-md hover:bg-gray-600';
            }
        });
        
        // Show/hide content
        this.tabs.forEach(tab => {
            const content = domUtils.getElement(tab.contentId);
            if (content) {
                domUtils.setVisible(content, tab.id === tabId);
            }
        });
        
        this.activeTab = tabId;
    }
}

// Toast notification component
export class ToastComponent {
    constructor() {
        this.container = null;
    }

    // Initialize toast container
    init() {
        this.container = domUtils.createElement('div', 'fixed top-4 right-4 z-50 space-y-2');
        document.body.appendChild(this.container);
        return this;
    }

    // Show toast message
    show(message, type = 'info', duration = 3000) {
        if (!this.container) this.init();
        
        const toast = domUtils.createElement('div', `p-4 rounded-lg shadow-lg text-white max-w-sm transform transition-all duration-300 ${
            type === 'success' ? 'bg-green-600' :
            type === 'warning' ? 'bg-yellow-600' :
            type === 'danger' ? 'bg-red-600' :
            'bg-blue-600'
        }`);
        
        toast.innerHTML = `
            <div class="flex justify-between items-start">
                <span>${message}</span>
                <button class="ml-4 text-white hover:text-gray-200">&times;</button>
            </div>
        `;
        
        // Auto-hide after duration
        if (duration > 0) {
            setTimeout(() => {
                this.remove(toast);
            }, duration);
        }
        
        // Add close event
        toast.querySelector('button').onclick = () => this.remove(toast);
        
        this.container.appendChild(toast);
        
        // Animation
        setTimeout(() => {
            toast.style.opacity = '1';
            toast.style.transform = 'translateY(0)';
        }, 10);
        
        return toast;
    }

    // Remove toast
    remove(toast) {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(-10px)';
        setTimeout(() => {
            if (this.container && toast.parentNode === this.container) {
                this.container.removeChild(toast);
            }
        }, 300);
    }
}

// Progress bar component
export class ProgressBarComponent {
    constructor(containerId) {
        this.container = domUtils.getElement(containerId);
        this.bar = null;
        this.fill = null;
        this.text = null;
    }

    // Initialize progress bar
    init() {
        if (!this.container) return;
        
        this.bar = domUtils.createElement('div', 'progress-bar');
        this.fill = domUtils.createElement('div', 'progress-bar-fill');
        this.fill.style.width = '0%';
        
        this.text = domUtils.createElement('div', 'text-xs text-gray-400 mt-1 text-center');
        this.text.textContent = '0%';
        
        this.bar.appendChild(this.fill);
        
        this.container.innerHTML = '';
        this.container.appendChild(this.bar);
        this.container.appendChild(this.text);
        
        return this;
    }

    // Update progress
    update(percent, text = null) {
        if (this.fill) {
            this.fill.style.width = `${percent}%`;
        }
        if (this.text) {
            this.text.textContent = text || `${Math.round(percent)}%`;
        }
        return this;
    }
}

// List component for displaying data
export class ListComponent {
    constructor(containerId) {
        this.container = domUtils.getElement(containerId);
        this.items = [];
        this.itemTemplate = null;
    }

    // Set item template
    setTemplate(templateFn) {
        this.itemTemplate = templateFn;
        return this;
    }

    // Add items to list
    addItems(items) {
        if (!this.container) return;
        
        this.items = [...this.items, ...items];
        this.render();
        
        return this;
    }

    // Remove items from list
    removeItems(itemIds) {
        this.items = this.items.filter(item => !itemIds.includes(item.id));
        this.render();
        return this;
    }

    // Clear all items
    clear() {
        this.items = [];
        this.container.innerHTML = '<div class="text-center text-gray-500 py-4">No items to display</div>';
        return this;
    }

    // Render list
    render() {
        if (!this.container) return;
        
        this.container.innerHTML = '';
        
        if (this.items.length === 0) {
            this.container.innerHTML = '<div class="text-center text-gray-500 py-4">No items to display</div>';
            return;
        }
        
        this.items.forEach(item => {
            const itemEl = this.itemTemplate ? this.itemTemplate(item) : this.defaultItemTemplate(item);
            this.container.appendChild(itemEl);
        });
    }

    // Default item template
    defaultItemTemplate(item) {
        const itemEl = domUtils.createElement('div', 'p-2 bg-gray-800 rounded mb-2');
        itemEl.textContent = JSON.stringify(item);
        return itemEl;
    }
}

// Initialize all components when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Any initialization code for components can go here
});