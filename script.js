/**
 * Password Security Dashboard Engine
 */

class PasswordAnalyzerEngine {
    constructor() {
        this.commonPasswords = [
            "123456", "password", "123456789", "12345678", "12345", 
            "qwerty", "password1", "111111", "1234567", "dragon", 
            "admin", "welcome", "iloveyou", "master", "sunshine"
        ];
        
        this.sequentialRegex = /(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i;
    }

    getPoolSize(password) {
        let pool = 0;
        if (/[a-z]/.test(password)) pool += 26;
        if (/[A-Z]/.test(password)) pool += 26;
        if (/[0-9]/.test(password)) pool += 10;
        if (/[^a-zA-Z0-9]/.test(password)) pool += 32;
        return pool;
    }

    calculateEntropy(password) {
        if (!password) return 0;
        const poolSize = this.getPoolSize(password);
        if (poolSize === 0) return 0;
        const entropy = password.length * (Math.log2(poolSize));
        return Math.round(entropy * 10) / 10;
    }

    estimateCrackTime(entropy) {
        if (entropy === 0) return "Instant";
        const combinations = Math.pow(2, entropy);
        const guessesPerSecond = 10000000000; // 10 Billion guesses/sec
        const seconds = combinations / guessesPerSecond;

        if (seconds < 1) return "Instant";
        if (seconds < 60) return `${Math.round(seconds)} Seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} Minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} Hours`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)} Days`;
        if (seconds < 3153600000) return `${Math.round(seconds / 31536000)} Years`;
        return "Centuries (Unbreakable)";
    }

    detectVulnerabilities(password) {
        const vulns = [];
        if (!password) return vulns;

        const lowerPass = password.toLowerCase();

        if (this.commonPasswords.some(common => lowerPass.includes(common))) {
            vulns.push({ type: 'danger', text: 'Contains a common blacklisted password pattern.' });
        }

        if (/(.)\1\1/.test(password)) {
            vulns.push({ type: 'warning', text: 'Contains repeated identical characters.' });
        }

        if (this.sequentialRegex.test(password)) {
            vulns.push({ type: 'warning', text: 'Contains sequential characters (e.g., "123" or "abc").' });
        }

        if (password.length < 8) {
            vulns.push({ type: 'danger', text: 'Password is critically short.' });
        }

        const uniqueChars = new Set(password).size;
        const uniqueRatio = uniqueChars / password.length;
        if (uniqueRatio < 0.5 && password.length > 5) {
            vulns.push({ type: 'warning', text: 'Low character diversity (too many duplicate characters).' });
        }

        return vulns;
    }

    calculateOverallScore(password, entropy, vulns) {
        if (!password) return 0;
        
        let score = Math.min(100, (entropy / 75) * 100);

        vulns.forEach(v => {
            if (v.type === 'danger') score -= 25;
            if (v.type === 'warning') score -= 10;
        });

        return Math.max(0, Math.min(100, Math.round(score)));
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const analyzer = new PasswordAnalyzerEngine();

    // Navigation Switcher Logic
    const navItems = document.querySelectorAll('.nav-item');
    const viewSections = document.querySelectorAll('.view-section');

    navItems.forEach(button => {
        button.addEventListener('click', () => {
            const targetId = button.getAttribute('data-target');

            // Switch active tab styling
            navItems.forEach(item => item.classList.remove('active'));
            button.classList.add('active');

            // Switch visible view section
            viewSections.forEach(section => {
                if (section.id === targetId) {
                    section.classList.add('active');
                } else {
                    section.classList.remove('active');
                }
            });
        });
    });

    // Analyzer UI Elements
    const passwordInput = document.getElementById('passwordInput');
    const toggleVisibilityBtn = document.getElementById('togglePasswordVisibility');
    const eyeIcon = document.getElementById('eyeIcon');
    const copyPasswordBtn = document.getElementById('copyPasswordBtn');

    const scoreText = document.getElementById('scoreText');
    const meterFill = document.getElementById('meterFill');
    const entropyValue = document.getElementById('entropyValue');
    const crackTimeValue = document.getElementById('crackTimeValue');
    const charCountValue = document.getElementById('charCountValue');
    const vulnerabilityList = document.getElementById('vulnerabilityList');

    const rules = {
        length: document.getElementById('rule-length'),
        uppercase: document.getElementById('rule-uppercase'),
        lowercase: document.getElementById('rule-lowercase'),
        number: document.getElementById('rule-number'),
        symbol: document.getElementById('rule-symbol'),
        unique: document.getElementById('rule-unique')
    };

    passwordInput.addEventListener('input', () => {
        analyze(passwordInput.value);
    });

    toggleVisibilityBtn.addEventListener('click', () => {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        eyeIcon.className = type === 'password' ? 'fa-solid fa-eye' : 'fa-solid fa-eye-slash';
    });

    copyPasswordBtn.addEventListener('click', () => {
        if (!passwordInput.value) return;
        navigator.clipboard.writeText(passwordInput.value);
        copyPasswordBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied';
        setTimeout(() => {
            copyPasswordBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy';
        }, 2000);
    });

    function analyze(password) {
        const length = password.length;
        const entropy = analyzer.calculateEntropy(password);
        const crackTime = analyzer.estimateCrackTime(entropy);
        const vulnerabilities = analyzer.detectVulnerabilities(password);
        const score = analyzer.calculateOverallScore(password, entropy, vulnerabilities);

        charCountValue.textContent = `${length} chars`;
        entropyValue.textContent = `${entropy} bits`;
        crackTimeValue.textContent = crackTime;
        scoreText.textContent = `${score}% (${getScoreLabel(score)})`;

        meterFill.style.width = `${score}%`;
        meterFill.style.backgroundColor = getScoreColor(score);

        updateRules(password);
        renderVulnerabilities(vulnerabilities, password);
    }

    function updateRules(password) {
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNum = /[0-9]/.test(password);
        const hasSym = /[^a-zA-Z0-9]/.test(password);
        const isLongEnough = password.length >= 12;
        const uniqueRatio = password.length > 0 ? (new Set(password).size / password.length) : 0;

        toggleRule(rules.length, isLongEnough);
        toggleRule(rules.uppercase, hasUpper);
        toggleRule(rules.lowercase, hasLower);
        toggleRule(rules.number, hasNum);
        toggleRule(rules.symbol, hasSym);
        toggleRule(rules.unique, uniqueRatio >= 0.6 && password.length > 0);
    }

    function toggleRule(element, isValid) {
        const icon = element.querySelector('.status-icon');
        if (isValid) {
            element.className = 'valid';
            icon.className = 'fa-solid fa-check status-icon';
        } else {
            element.className = 'invalid';
            icon.className = 'fa-solid fa-xmark status-icon';
        }
    }

    function renderVulnerabilities(vulns, password) {
        vulnerabilityList.innerHTML = '';
        if (!password) {
            vulnerabilityList.innerHTML = '<div class="empty-state">Enter a password above to begin vulnerability scanning.</div>';
            return;
        }

        if (vulns.length === 0) {
            vulnerabilityList.innerHTML = '<div class="vuln-item" style="background: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; color: #86efac;"><i class="fa-solid fa-shield-check"></i> No significant patterns or weaknesses detected!</div>';
            return;
        }

        vulns.forEach(v => {
            const div = document.createElement('div');
            div.className = `vuln-item vuln-${v.type}`;
            div.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${v.text}`;
            vulnerabilityList.appendChild(div);
        });
    }

    function getScoreColor(score) {
        if (score < 30) return '#ef4444';
        if (score < 60) return '#eab308';
        if (score < 85) return '#38bdf8';
        return '#22c55e';
    }

    function getScoreLabel(score) {
        if (score === 0) return 'Empty';
        if (score < 30) return 'Weak';
        if (score < 60) return 'Moderate';
        if (score < 85) return 'Strong';
        return 'Very Secure';
    }

    // Generator UI Logic
    const genLengthSlider = document.getElementById('genLength');
    const genLengthVal = document.getElementById('genLengthVal');
    const incUpper = document.getElementById('incUpper');
    const incLower = document.getElementById('incLower');
    const incNumbers = document.getElementById('incNumbers');
    const incSymbols = document.getElementById('incSymbols');
    const generateBtn = document.getElementById('generateBtn');
    const generatedResult = document.getElementById('generatedResult');
    const copyGeneratedBtn = document.getElementById('copyGeneratedBtn');

    genLengthSlider.addEventListener('input', (e) => {
        genLengthVal.textContent = e.target.value;
    });

    generateBtn.addEventListener('click', () => {
        const length = parseInt(genLengthSlider.value);
        const chars = {
            upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            lower: 'abcdefghijklmnopqrstuvwxyz',
            numbers: '0123456789',
            symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
        };

        let validChars = '';
        if (incUpper.checked) validChars += chars.upper;
        if (incLower.checked) validChars += chars.lower;
        if (incNumbers.checked) validChars += chars.numbers;
        if (incSymbols.checked) validChars += chars.symbols;

        if (!validChars) {
            alert('Please select at least one character type!');
            return;
        }

        let generatedPassword = '';
        const cryptoObj = window.crypto || window.msCrypto;
        const randomValues = new Uint32Array(length);
        cryptoObj.getRandomValues(randomValues);

        for (let i = 0; i < length; i++) {
            generatedPassword += validChars[randomValues[i] % validChars.length];
        }

        generatedResult.value = generatedPassword;
    });

    copyGeneratedBtn.addEventListener('click', () => {
        if (!generatedResult.value) return;
        navigator.clipboard.writeText(generatedResult.value);
        copyGeneratedBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied';
        setTimeout(() => {
            copyGeneratedBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy';
        }, 2000);
    });
});