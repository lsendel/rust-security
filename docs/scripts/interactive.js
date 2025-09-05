// Interactive features for Rust Security Platform documentation

(function() {
    'use strict';

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        initializeInteractiveFeatures();
    });

    function initializeInteractiveFeatures() {
        // Add copy functionality to code blocks
        addCopyButtons();
        
        // Add API method styling
        styleApiMethods();
        
        // Add interactive callouts
        processCallouts();
        
        // Initialize code playground features
        initializeCodePlayground();
        
        // Add security-specific enhancements
        addSecurityEnhancements();
    }

    function addCopyButtons() {
        const codeBlocks = document.querySelectorAll('pre code');
        
        codeBlocks.forEach(function(codeBlock) {
            const pre = codeBlock.parentNode;
            if (pre.classList.contains('playground')) {
                return; // Already has playground functionality
            }
            
            const button = document.createElement('button');
            button.className = 'copy-button';
            button.textContent = '📋';
            button.title = 'Copy to clipboard';
            
            button.addEventListener('click', function() {
                navigator.clipboard.writeText(codeBlock.textContent).then(function() {
                    button.textContent = '✅';
                    setTimeout(function() {
                        button.textContent = '📋';
                    }, 2000);
                }).catch(function() {
                    button.textContent = '❌';
                    setTimeout(function() {
                        button.textContent = '📋';
                    }, 2000);
                });
            });
            
            pre.style.position = 'relative';
            pre.appendChild(button);
        });
    }

    function styleApiMethods() {
        // Find and style API method indicators
        const methodRegex = /\b(GET|POST|PUT|DELETE|PATCH)\b\s+([\/\w\{\}]+)/g;
        
        document.querySelectorAll('p, li, td').forEach(function(element) {
            const text = element.textContent;
            if (methodRegex.test(text)) {
                element.innerHTML = element.innerHTML.replace(
                    /\b(GET|POST|PUT|DELETE|PATCH)\b(\s+)([\w\/\{\}]+)/g,
                    '<span class="api-method $1">$1</span>$2<code>$3</code>'
                );
            }
        });
    }

    function processCallouts() {
        // Convert markdown-style callouts to styled divs
        const calloutRegex = /^>\s*\*\*(NOTE|WARNING|DANGER|SUCCESS|SECURITY):\*\*(.+)$/gm;
        
        document.querySelectorAll('blockquote').forEach(function(blockquote) {
            const text = blockquote.innerHTML;
            const matches = text.match(/^\s*<p><strong>(NOTE|WARNING|DANGER|SUCCESS|SECURITY):<\/strong>(.+)<\/p>\s*$/);
            
            if (matches) {
                const type = matches[1].toLowerCase();
                const content = matches[2].trim();
                
                blockquote.className = 'security-' + (type === 'note' ? 'note' : 
                                                     type === 'warning' ? 'warning' :
                                                     type === 'danger' ? 'danger' :
                                                     type === 'success' ? 'success' :
                                                     type === 'security' ? 'note' : 'note');
                blockquote.innerHTML = '<p>' + content + '</p>';
            }
        });
    }

    function initializeCodePlayground() {
        // Enhance playground functionality for Rust code examples
        document.querySelectorAll('pre.playground').forEach(function(playground) {
            // Add run button if not present
            if (!playground.querySelector('.play-button')) {
                const runButton = document.createElement('button');
                runButton.className = 'play-button';
                runButton.textContent = '▶️ Run';
                runButton.title = 'Run this code example';
                
                runButton.addEventListener('click', function() {
                    runCodeExample(playground);
                });
                
                playground.appendChild(runButton);
            }
        });
    }

    function runCodeExample(playground) {
        const code = playground.querySelector('code').textContent;
        
        // For security platform, we'll show a simulation rather than actual execution
        showCodeExecution(playground, code);
    }

    function showCodeExecution(playground, code) {
        const output = document.createElement('div');
        output.className = 'code-output';
        
        // Simulate execution based on code content
        let result = '';
        
        if (code.includes('TokenRequest')) {
            result = '✅ Token request validated successfully\n🔑 JWT token generated: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...';
        } else if (code.includes('SecurityContext')) {
            result = '🔍 Security context initialized\n📊 Threat level: LOW\n🌐 Client IP validated';
        } else if (code.includes('validate_input')) {
            result = '✅ Input validation passed\n🛡️ No security threats detected';
        } else if (code.includes('MvpPolicyEngine')) {
            result = '🚀 Policy engine initialized\n📋 Default policies loaded\n✅ Ready for authorization requests';
        } else {
            result = '✅ Code executed successfully\n📝 Output would appear here in a real environment';
        }
        
        output.innerHTML = '<pre><strong>Output:</strong>\n' + result + '</pre>';
        
        // Remove existing output
        const existingOutput = playground.parentNode.querySelector('.code-output');
        if (existingOutput) {
            existingOutput.remove();
        }
        
        // Add new output
        playground.parentNode.appendChild(output);
        
        // Auto-hide after 10 seconds
        setTimeout(function() {
            if (output.parentNode) {
                output.remove();
            }
        }, 10000);
    }

    function addSecurityEnhancements() {
        // Add security badges to relevant sections
        addSecurityBadges();
        
        // Highlight security-critical code
        highlightSecurityCode();
        
        // Add interactive security tips
        addSecurityTips();
    }

    function addSecurityBadges() {
        const securityKeywords = ['authentication', 'authorization', 'encryption', 'jwt', 'token', 'security'];
        
        document.querySelectorAll('h1, h2, h3, h4').forEach(function(heading) {
            const text = heading.textContent.toLowerCase();
            
            securityKeywords.forEach(function(keyword) {
                if (text.includes(keyword)) {
                    const badge = document.createElement('span');
                    badge.className = 'status-badge stable';
                    badge.textContent = '🔒 Security';
                    heading.appendChild(document.createTextNode(' '));
                    heading.appendChild(badge);
                }
            });
        });
    }

    function highlightSecurityCode() {
        document.querySelectorAll('code').forEach(function(code) {
            const text = code.textContent;
            
            // Highlight security-related patterns
            if (text.includes('password') || text.includes('secret') || text.includes('key')) {
                code.style.background = '#fff3cd';
                code.style.border = '1px solid #ffeaa7';
                code.title = '⚠️ Security-sensitive code';
            }
        });
    }

    function addSecurityTips() {
        // Add tooltips to security-related elements
        const securityElements = document.querySelectorAll('[title*="security"], [title*="Security"]');
        
        securityElements.forEach(function(element) {
            element.addEventListener('mouseenter', function() {
                showSecurityTip(element);
            });
        });
    }

    function showSecurityTip(element) {
        const tip = document.createElement('div');
        tip.className = 'security-tip';
        tip.innerHTML = '🔒 This is a security-related feature. Review carefully in production.';
        
        document.body.appendChild(tip);
        
        const rect = element.getBoundingClientRect();
        tip.style.position = 'absolute';
        tip.style.top = (rect.bottom + window.scrollY + 5) + 'px';
        tip.style.left = (rect.left + window.scrollX) + 'px';
        tip.style.background = '#2c5aa0';
        tip.style.color = 'white';
        tip.style.padding = '0.5rem';
        tip.style.borderRadius = '4px';
        tip.style.zIndex = '1000';
        tip.style.fontSize = '0.8rem';
        tip.style.maxWidth = '300px';
        
        setTimeout(function() {
            if (tip.parentNode) {
                tip.remove();
            }
        }, 3000);
    }

    // Add CSS for interactive elements
    const style = document.createElement('style');
    style.textContent = `
        .copy-button {
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            background: #2c5aa0;
            color: white;
            border: none;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8rem;
            opacity: 0;
            transition: opacity 0.2s;
        }
        
        pre:hover .copy-button {
            opacity: 1;
        }
        
        .play-button {
            position: absolute;
            bottom: 0.5rem;
            right: 0.5rem;
            background: #28a745;
            color: white;
            border: none;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8rem;
        }
        
        .code-output {
            margin: 1rem 0;
            padding: 1rem;
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            border-left: 4px solid #28a745;
        }
        
        .code-output pre {
            margin: 0;
            background: none;
            border: none;
            padding: 0;
        }
        
        .api-method.GET { background: #28a745; }
        .api-method.POST { background: #2c5aa0; }
        .api-method.PUT { background: #ffc107; color: black; }
        .api-method.DELETE { background: #dc3545; }
        .api-method.PATCH { background: #6f42c1; }
    `;
    document.head.appendChild(style);

})();