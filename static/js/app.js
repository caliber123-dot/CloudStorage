// JavaScript for handling file uploads and UI interactions
document.addEventListener('DOMContentLoaded', function() {
    // File upload preview and handling
    const fileUploads = document.querySelectorAll('input[type="file"]');
    const uploadLists = document.querySelectorAll('.upload-list');
    
    fileUploads.forEach((fileUpload, index) => {
        const uploadList = uploadLists[index];
        
        fileUpload.addEventListener('change', function(e) {
            uploadList.innerHTML = '';
            
            if (this.files.length > 0) {
                Array.from(this.files).forEach(file => {
                    const fileItem = document.createElement('div');
                    fileItem.className = 'upload-item d-flex align-items-center mb-2 p-2 border rounded';
                    
                    // File icon based on type
                    let iconClass = 'bi-file-earmark';
                    if (file.type.includes('image')) {
                        iconClass = 'bi-file-earmark-image';
                    } else if (file.type.includes('pdf')) {
                        iconClass = 'bi-file-earmark-pdf';
                    } else if (file.type.includes('word') || file.type.includes('document')) {
                        iconClass = 'bi-file-earmark-word';
                    } else if (file.type.includes('excel') || file.type.includes('spreadsheet')) {
                        iconClass = 'bi-file-earmark-excel';
                    } else if (file.type.includes('zip') || file.type.includes('archive')) {
                        iconClass = 'bi-file-earmark-zip';
                    } else if (file.type.includes('text')) {
                        iconClass = 'bi-file-earmark-text';
                    }
                    
                    // Format file size
                    let fileSize = file.size;
                    let sizeUnit = 'B';
                    if (fileSize > 1024) {
                        fileSize = (fileSize / 1024).toFixed(2);
                        sizeUnit = 'KB';
                    }
                    if (fileSize > 1024) {
                        fileSize = (fileSize / 1024).toFixed(2);
                        sizeUnit = 'MB';
                    }
                    
                    fileItem.innerHTML = `
                        <i class="bi ${iconClass} me-2"></i>
                        <div class="flex-grow-1">
                            <div class="fw-bold">${file.name}</div>
                            <div class="small text-muted">${fileSize} ${sizeUnit}</div>
                        </div>
                    `;
                    
                    uploadList.appendChild(fileItem);
                });
            }
        });
        
        // Drag and drop handling
        const uploadArea = fileUpload.closest('.upload-area');
        
        if (uploadArea) {
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                uploadArea.addEventListener(eventName, preventDefaults, false);
            });
            
            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }
            
            ['dragenter', 'dragover'].forEach(eventName => {
                uploadArea.addEventListener(eventName, highlight, false);
            });
            
            ['dragleave', 'drop'].forEach(eventName => {
                uploadArea.addEventListener(eventName, unhighlight, false);
            });
            
            function highlight() {
                uploadArea.classList.add('highlight');
            }
            
            function unhighlight() {
                uploadArea.classList.remove('highlight');
            }
            
            uploadArea.addEventListener('drop', handleDrop, false);
            
            function handleDrop(e) {
                const dt = e.dataTransfer;
                const files = dt.files;
                fileUpload.files = files;
                
                // Trigger change event
                const event = new Event('change');
                fileUpload.dispatchEvent(event);
            }
        }
    });
    
    // Modal z-index fix for stacking
    const modals = document.querySelectorAll('.modal');
    let zIndex = 1050;
    
    modals.forEach(modal => {
        modal.addEventListener('show.bs.modal', function() {
            zIndex += 10;
            this.style.zIndex = zIndex;
        });
        
        modal.addEventListener('hidden.bs.modal', function() {
            if (document.querySelectorAll('.modal.show').length) {
                document.body.classList.add('modal-open');
            }
        });
    });
    
    // File preview handling
    const previewLinks = document.querySelectorAll('.preview-file');
    const previewModal = document.getElementById('previewModal');
    
    if (previewLinks.length > 0 && previewModal) {
        previewLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const fileId = this.getAttribute('data-file-id');
                const fileType = this.getAttribute('data-file-type');
                const fileName = this.getAttribute('data-file-name');
                
                document.getElementById('previewModalLabel').textContent = fileName;
                document.getElementById('previewDownloadBtn').href = `/api/download/${fileId}`;
                
                const previewContent = document.getElementById('previewContent');
                previewContent.innerHTML = '<div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div>';
                
                // Load preview based on file type
                if (fileType && fileType.includes('image')) {
                    const img = document.createElement('img');
                    img.src = `/api/preview/${fileId}`;
                    img.className = 'img-fluid';
                    img.alt = fileName;
                    img.onload = function() {
                        previewContent.innerHTML = '';
                        previewContent.appendChild(img);
                    };
                } else if (fileType && fileType.includes('pdf')) {
                    const iframe = document.createElement('iframe');
                    iframe.src = `/api/preview/${fileId}`;
                    iframe.width = '100%';
                    iframe.height = '500px';
                    previewContent.innerHTML = '';
                    previewContent.appendChild(iframe);
                } else if (fileType && (fileType.includes('text') || fileType.includes('json') || fileType.includes('xml') || fileType.includes('html'))) {
                    fetch(`/api/preview/${fileId}`)
                        .then(response => response.text())
                        .then(text => {
                            const pre = document.createElement('pre');
                            pre.className = 'text-start';
                            pre.textContent = text;
                            previewContent.innerHTML = '';
                            previewContent.appendChild(pre);
                        });
                } else {
                    previewContent.innerHTML = '<p>Preview not available for this file type. Please download the file to view it.</p>';
                }
                
                const modal = new bootstrap.Modal(previewModal);
                modal.show();
            });
        });
    }
    
    // Rename item handling
    const renameLinks = document.querySelectorAll('.rename-item');
    const renameModal = document.getElementById('renameModal');
    
    if (renameLinks.length > 0 && renameModal) {
        renameLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const itemId = this.getAttribute('data-item-id');
                const itemName = this.getAttribute('data-item-name');
                
                document.getElementById('renameForm').action = `/api/rename/${itemId}`;
                document.getElementById('newName').value = itemName;
                
                const modal = new bootstrap.Modal(renameModal);
                modal.show();
            });
        });
    }
    
    // Share item handling
    const shareLinks = document.querySelectorAll('.share-item');
    const shareModal = document.getElementById('shareModal');
    
    if (shareLinks.length > 0 && shareModal) {
        shareLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const itemId = this.getAttribute('data-item-id');
                const itemName = this.getAttribute('data-item-name');
                
                document.getElementById('shareForm').action = `/api/share/${itemId}`;
                document.getElementById('shareModalLabel').textContent = `Share: ${itemName}`;
                
                const modal = new bootstrap.Modal(shareModal);
                modal.show();
            });
        });
        
        // Toggle share type
        const shareTypeUser = document.getElementById('shareTypeUser');
        const shareTypePublic = document.getElementById('shareTypePublic');
        const userEmailField = document.getElementById('userEmailField');
        const isPublicInput = document.getElementById('isPublic');
        
        if (shareTypeUser && shareTypePublic) {
            shareTypeUser.addEventListener('change', function() {
                userEmailField.style.display = 'block';
                isPublicInput.value = 'false';
            });
            
            shareTypePublic.addEventListener('change', function() {
                userEmailField.style.display = 'none';
                isPublicInput.value = 'true';
            });
        }
    }
    
    // Theme switching functionality
    const themeSwitch = document.getElementById('themeSwitch');
    
    // Set initial theme based on current setting
    if (themeSwitch) {
        themeSwitch.addEventListener('change', function() {
            const newTheme = this.checked ? 'dark' : 'light';
            
            // Update theme via AJAX
            fetch('/toggle-theme', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ theme: newTheme })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Update body theme
                    document.body.setAttribute('data-bs-theme', newTheme);
                    
                    // Update theme switch state
                    themeSwitch.checked = newTheme === 'dark';
                    
                    // Show success message
                    const alertDiv = document.createElement('div');
                    alertDiv.className = 'alert alert-success alert-dismissible fade show position-fixed top-0 end-0 m-3';
                    alertDiv.innerHTML = `
                        Theme updated to ${newTheme}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    `;
                    document.body.appendChild(alertDiv);
                    
                    // Remove alert after 3 seconds
                    setTimeout(() => {
                        alertDiv.remove();
                    }, 3000);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                // Show error message
                const alertDiv = document.createElement('div');
                alertDiv.className = 'alert alert-danger alert-dismissible fade show position-fixed top-0 end-0 m-3';
                alertDiv.innerHTML = `
                    Error updating theme
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                `;
                document.body.appendChild(alertDiv);
                
                // Remove alert after 3 seconds
                setTimeout(() => {
                    alertDiv.remove();
                }, 3000);
            });
        });
    }
    
    // Sort functionality
    const sortLinks = document.querySelectorAll('.sort-link');
    sortLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            window.location.href = this.href;
        });
    });
});

// Add CSS for upload area highlight
document.addEventListener('DOMContentLoaded', function() {
    const style = document.createElement('style');
    style.textContent = `
        .upload-area.highlight {
            border-color: #0d6efd !important;
            background-color: rgba(13, 110, 253, 0.05);
        }
        
        .file-card {
            transition: all 0.2s ease;
            position: relative;
            z-index: 1;
        }
        
        .file-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            z-index: 2;
        }
        
        .modal {
            z-index: 1050;
        }
        
        .modal-backdrop {
            z-index: 1040;
        }
    `;
    document.head.appendChild(style);
});
