// Main JavaScript for PromptDefender

// Global variables
let currentThreatLevel = 'secure';
let autoRefreshInterval;

// Initialize application
function initializeApp() {
    console.log('🚀 Initializing PromptDefender...');
    
    // Load initial data
    loadSystemStatus();
    updateGlobalStatus();
    
    // Start auto-refresh for real-time features
    startAutoRefresh();
    
    // Initialize event listeners
    initializeEventListeners();
    
    console.log('✅ PromptDefender initialized successfully');
}

// Load system status
function loadSystemStatus() {
    fetch('/health')
        .then(response => response.json())
        .then(data => {
            updateSystemStatusDisplay(data);
        })
        .catch(error => {
            console.error('Error loading system status:', error);
        });
}

// Update system status display
function updateSystemStatusDisplay(status) {
    const statusIndicator = document.getElementById('globalStatusIndicator');
    
    if (status.status === 'healthy' && status.model_loaded) {
        statusIndicator.className = 'status-indicator status-good';
        statusIndicator.title = 'System Healthy';
    } else {
        statusIndicator.className = 'status-indicator status-error';
        statusIndicator.title = 'System Issues Detected';
    }
}

// Update global threat status
function updateGlobalStatus() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            updateThreatLevel(data);
        })
        .catch(error => {
            console.error('Error updating global status:', error);
        });
}

// Update threat level based on stats
function updateThreatLevel(stats) {
    const threatCount = stats.total_blocked || 0;
    let newThreatLevel = 'secure';
    
    if (threatCount > 10) {
        newThreatLevel = 'high';
    } else if (threatCount > 3) {
        newThreatLevel = 'medium';
    } else if (threatCount > 0) {
        newThreatLevel = 'low';
    }
    
    if (newThreatLevel !== currentThreatLevel) {
        currentThreatLevel = newThreatLevel;
        updateStatusIndicator(newThreatLevel);
    }
}

// Update status indicator
function updateStatusIndicator(level) {
    const indicator = document.getElementById('globalStatusIndicator');
    indicator.className = 'status-indicator status-' + level;
    
    // Update title based on threat level
    const titles = {
        'secure': 'All Systems Secure',
        'low': 'Low Threat Level',
        'medium': 'Medium Threat Level', 
        'high': 'High Threat Level - Attention Required'
    };
    indicator.title = titles[level] || 'Unknown Status';
}

// Start auto-refresh for real-time features
function startAutoRefresh() {
    // Clear existing interval
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
    
    // Set new interval (30 seconds)
    autoRefreshInterval = setInterval(() => {
        updateGlobalStatus();
        loadSystemStatus();
    }, 30000);
}

// Initialize event listeners
function initializeEventListeners() {
    // Keyboard shortcuts
    document.addEventListener('keydown', function(event) {
        // Ctrl + / for focus search
        if (event.ctrlKey && event.key === '/') {
            event.preventDefault();
            const searchInput = document.querySelector('input[type="search"], input[placeholder*="search" i]');
            if (searchInput) {
                searchInput.focus();
            }
        }
        
        // Escape to clear inputs
        if (event.key === 'Escape') {
            const activeElement = document.activeElement;
            if (activeElement && (activeElement.tagName === 'INPUT' || activeElement.tagName === 'TEXTAREA')) {
                activeElement.value = '';
            }
        }
    });
    
    // Responsive menu toggle for mobile
    initializeMobileMenu();
}

// Mobile menu initialization
function initializeMobileMenu() {
    const menuToggle = document.createElement('button');
    menuToggle.className = 'menu-toggle';
    menuToggle.innerHTML = '<i class="fas fa-bars"></i>';
    menuToggle.style.display = 'none';
    
    const headerContent = document.querySelector('.header-content');
    const navMenu = document.querySelector('.nav-menu');
    
    if (headerContent && navMenu) {
        headerContent.appendChild(menuToggle);
        
        menuToggle.addEventListener('click', function() {
            navMenu.classList.toggle('mobile-open');
        });
        
        // Check screen size and toggle menu visibility
        function checkScreenSize() {
            if (window.innerWidth <= 768) {
                menuToggle.style.display = 'block';
                navMenu.classList.add('mobile-hidden');
            } else {
                menuToggle.style.display = 'none';
                navMenu.classList.remove('mobile-hidden', 'mobile-open');
            }
        }
        
        checkScreenSize();
        window.addEventListener('resize', checkScreenSize);
    }
}

// Export logs function
function exportLogs() {
    fetch('/api/logs')
        .then(response => response.json())
        .then(data => {
            if (data.logs && data.logs.length > 0) {
                exportToCSV(data.logs);
            } else {
                alert('No logs available to export');
            }
        })
        .catch(error => {
            console.error('Error exporting logs:', error);
            alert('Error exporting logs. Please try again.');
        });
}

// Export data to CSV
function exportToCSV(data) {
    let csvContent = '';
    
    // Add headers
    const headers = Object.keys(data[0]);
    csvContent += headers.join(',') + '\n';
    
    // Add data rows
    data.forEach(row => {
        const values = headers.map(header => {
            let value = row[header] || '';
            // Escape quotes and wrap in quotes if contains comma
            value = String(value).replace(/"/g, '""');
            if (String(value).includes(',')) {
                value = '"' + value + '"';
            }
            return value;
        });
        csvContent += values.join(',') + '\n';
    });
    
    // Create and trigger download
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `promptdefender_export_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

// Utility function for making API calls
async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(endpoint, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API call failed:', error);
        throw error;
    }
}

// Show notification
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${getNotificationIcon(type)}"></i>
            <span>${message}</span>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

// Get appropriate icon for notification type
function getNotificationIcon(type) {
    const icons = {
        'info': 'info-circle',
        'success': 'check-circle',
        'warning': 'exclamation-triangle',
        'error': 'exclamation-circle'
    };
    return icons[type] || 'info-circle';
}

// Format date for display
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

// Format confidence percentage
function formatConfidence(confidence) {
    return (confidence * 100).toFixed(1) + '%';
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initializeApp);

// Export functions for use in other scripts
window.PromptDefender = {
    apiCall,
    showNotification,
    formatDate,
    formatConfidence,
    exportLogs
};