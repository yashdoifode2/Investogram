document.addEventListener('DOMContentLoaded', function() {
    // ========================================
    // SIDEBAR TOGGLE
    // ========================================
    const toggleBtn = document.getElementById('toggleSidebar');
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    function toggleSidebar() {
        if (!sidebar) return;
        const isOpen = sidebar.classList.toggle('open');
        if (overlay) {
            overlay.classList.toggle('active', isOpen);
        }
        document.body.style.overflow = isOpen ? 'hidden' : '';
    }
    
    function closeSidebar() {
        if (sidebar) {
            sidebar.classList.remove('open');
        }
        if (overlay) {
            overlay.classList.remove('active');
        }
        document.body.style.overflow = '';
    }
    
    if (toggleBtn) {
        toggleBtn.addEventListener('click', toggleSidebar);
    }
    
    if (overlay) {
        overlay.addEventListener('click', closeSidebar);
    }
    
    // Close sidebar on escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeSidebar();
        }
    });
    
    // Close sidebar on window resize (if going from mobile to desktop)
    window.addEventListener('resize', function() {
        if (window.innerWidth > 768 && sidebar && sidebar.classList.contains('open')) {
            closeSidebar();
        }
    });
    
    // ========================================
    // USER DROPDOWN
    // ========================================
    const userDropdown = document.getElementById('userDropdown');
    const dropdownMenu = document.getElementById('dropdownMenu');
    
    if (userDropdown && dropdownMenu) {
        userDropdown.addEventListener('click', function(e) {
            e.stopPropagation();
            const isActive = this.classList.toggle('active');
            dropdownMenu.classList.toggle('show', isActive);
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', function(e) {
            if (!userDropdown.contains(e.target)) {
                userDropdown.classList.remove('active');
                dropdownMenu.classList.remove('show');
            }
        });
    }
    
    // ========================================
    // CLOSE ALERTS
    // ========================================
    const closeButtons = document.querySelectorAll('.close-alert');
    closeButtons.forEach(function(btn) {
        btn.addEventListener('click', function() {
            const alert = this.closest('.alert');
            if (alert) {
                alert.style.transition = 'all 0.3s ease';
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-10px)';
                setTimeout(function() {
                    alert.remove();
                }, 300);
            }
        });
    });
    
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-error)');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            if (alert && alert.parentNode) {
                alert.style.transition = 'all 0.3s ease';
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-10px)';
                setTimeout(function() {
                    if (alert.parentNode) {
                        alert.remove();
                    }
                }, 300);
            }
        }, 5000);
    });
    
    // ========================================
    // FORM VALIDATION HELPER
    // ========================================
    window.validateForm = function(formId) {
        const form = document.getElementById(formId);
        if (!form) return true;
        
        const inputs = form.querySelectorAll('input[required], textarea[required], select[required]');
        let isValid = true;
        
        inputs.forEach(function(input) {
            if (!input.value.trim()) {
                input.classList.add('error');
                isValid = false;
            } else {
                input.classList.remove('error');
            }
        });
        
        return isValid;
    };
    
    // ========================================
    // IMAGE PREVIEW FOR PROFILE UPLOAD
    // ========================================
    window.previewImage = function(input, previewId) {
        if (input.files && input.files[0]) {
            const reader = new FileReader();
            reader.onload = function(e) {
                const preview = document.getElementById(previewId);
                if (preview) {
                    preview.src = e.target.result;
                }
            };
            reader.readAsDataURL(input.files[0]);
        }
    };
    
    // ========================================
    // PASSWORD STRENGTH INDICATOR
    // ========================================
    window.checkPasswordStrength = function(password) {
        let strength = 0;
        if (password.length >= 8) strength++;
        if (password.match(/[a-z]+/)) strength++;
        if (password.match(/[A-Z]+/)) strength++;
        if (password.match(/[0-9]+/)) strength++;
        if (password.match(/[$@#&!]+/)) strength++;
        return strength;
    };
    
    // ========================================
    // KEYBOARD SHORTCUTS
    // ========================================
    document.addEventListener('keydown', function(e) {
        // Ctrl + K or Cmd + K to toggle sidebar
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            toggleSidebar();
        }
    });
    
    // ========================================
    // TOOLTIPS
    // ========================================
    function initTooltips() {
        const tooltips = document.querySelectorAll('[data-tooltip]');
        tooltips.forEach(function(el) {
            let timeoutId;
            
            el.addEventListener('mouseenter', function(e) {
                clearTimeout(timeoutId);
                const tooltip = document.createElement('div');
                tooltip.className = 'tooltip';
                tooltip.textContent = this.dataset.tooltip;
                tooltip.style.cssText = `
                    position: fixed;
                    background: var(--bg-secondary);
                    color: var(--text-primary);
                    padding: 6px 12px;
                    border-radius: 6px;
                    font-size: 0.8rem;
                    border: 1px solid var(--border-color);
                    z-index: 9999;
                    pointer-events: none;
                    box-shadow: var(--shadow-md);
                    max-width: 200px;
                    white-space: nowrap;
                `;
                
                const rect = this.getBoundingClientRect();
                tooltip.style.top = (rect.top - 10) + 'px';
                tooltip.style.left = (rect.left + rect.width / 2 - 100) + 'px';
                tooltip.style.transform = 'translateY(-100%)';
                
                document.body.appendChild(tooltip);
                
                timeoutId = setTimeout(() => {
                    if (tooltip.parentNode) {
                        tooltip.remove();
                    }
                }, 2000);
                
                this.addEventListener('mouseleave', function() {
                    clearTimeout(timeoutId);
                    if (tooltip.parentNode) {
                        tooltip.remove();
                    }
                });
            });
        });
    }
    
    initTooltips();
    
    console.log('🚀 MyProject initialized successfully!');
});