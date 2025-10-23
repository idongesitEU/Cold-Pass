// --- Ensure DOM is loaded before setting up event listeners ---
document.addEventListener('DOMContentLoaded', () => {
    // --- License Verification with OpenPGP ---
    const publicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=Vm9K
-----END PGP PUBLIC KEY BLOCK-----`;
    async function verifyLicenseKey() {
        const licenseKey = document.getElementById('licenseKey').value.trim();
        const licenseMessage = document.getElementById('licenseMessage');
        const verifyBtn = document.getElementById('verifyLicenseBtn');
        if (!licenseKey) {
            licenseMessage.innerHTML = 'Enter a License Key.<br><br> Please support the developer by purchasing a license by contacting <strong><a href="mailto:idongesit.fpg@gmail.com"> idongesit.fpg@gmail.com  </a></strong> <br><br><br>The license cost only <span style="color:green">$30</span>';
            licenseMessage.className = 'license-message license-invalid';
            licenseMessage.style.display = 'block';
            return;
        }
        // Show verifying state
        verifyBtn.textContent = 'Verifying...';
        verifyBtn.disabled = true;
        licenseMessage.textContent = 'Verifying license key...';
        licenseMessage.className = 'license-message license-verifying';
        licenseMessage.style.display = 'block';
        try {
            const isValid = await validateLicenseKeyWithPGP(licenseKey);
            if (isValid) {
                licenseMessage.textContent = 'License key verified successfully! Thank you for supporting the developer.';
                licenseMessage.className = 'license-message license-valid';
                licenseMessage.style.display = 'block';
                // Store verification in localStorage
                localStorage.setItem('licenseVerified', 'true');
                localStorage.setItem('licenseKey', licenseKey);
                // Hide the license section after successful verification
                setTimeout(() => {
                    document.querySelector('.license-section').style.display = 'none';
                }, 3000);
            } else {
                licenseMessage.innerHTML = 'Invalid license key. The signature could not be verified. Please support the developer by purchasing a license by contacting <strong><a href="mailto:idongesit.fpg@gmail.com"> idongesit.fpg@gmail.com  </a></strong> <br><br><br>The license cost only <span style="color:green">$30</span>';
                licenseMessage.className = 'license-message license-invalid';
                licenseMessage.style.display = 'block';
                // Clear any previous verification
                localStorage.removeItem('licenseVerified');
                localStorage.removeItem('licenseKey');
            }
        } catch (error) {
            console.error('License verification error:', error);
            licenseMessage.innerHTML = 'Error verifying license key. Please ensure you entered a valid PGP signed message. Support the developer by purchasing a license by contacting <strong><a href="mailto:idongesit.fpg@gmail.com"> idongesit.fpg@gmail.com  </a></strong> <br><br><br>The license cost only <span style="color:green">$30</span>';
            licenseMessage.className = 'license-message license-invalid';
            licenseMessage.style.display = 'block';
        } finally {
            // Reset button state
            verifyBtn.textContent = 'Verify License';
            verifyBtn.disabled = false;
        }
    }
    async function validateLicenseKeyWithPGP(licenseKey) {
        try {
            // Parse the public key
            const publicKeyObj = await openpgp.readKey({
                armoredKey: publicKey
            });
            let message;
            let verificationResult;
            // Check if it's a cleartext signed message
            if (licenseKey.includes('-----BEGIN PGP SIGNED MESSAGE-----')) {
                // For cleartext signed messages
                message = await openpgp.readCleartextMessage({
                    cleartextMessage: licenseKey
                });
                verificationResult = await openpgp.verify({
                    message: message,
                    verificationKeys: publicKeyObj
                });
            } else {
                // For regular signed messages
                message = await openpgp.readMessage({
                    armoredMessage: licenseKey
                });
                verificationResult = await openpgp.verify({
                    message: message,
                    verificationKeys: publicKeyObj
                });
            }
            // Check if signature is valid
            const {
                signatures
            } = verificationResult;
            if (signatures && signatures.length > 0) {
                // Check each signature
                for (const signature of signatures) {
                    try {
                        const valid = await signature.verified;
                        if (valid) {
                            console.log('License key verified successfully');
                            console.log('License message:', verificationResult.data);
                            return true;
                        }
                    } catch (e) {
                        console.error('Signature verification failed:', e);
                        // Continue to check other signatures
                    }
                }
                console.error('No valid signatures found');
                return false;
            } else {
                console.error('No signatures found in the message');
                return false;
            }
        } catch (error) {
            console.error('PGP verification error:', error);
            return false;
        }
    }
    // Check for existing license verification on page load
    function checkExistingLicense() {
        const isVerified = localStorage.getItem('licenseVerified') === 'true';
        const licenseKey = localStorage.getItem('licenseKey');
        if (isVerified && licenseKey) {
            // Auto-verify on page load
            document.getElementById('licenseKey').value = licenseKey;
            document.getElementById('licenseMessage').textContent = 'License key verified! Thank you for your support.';
            document.getElementById('licenseMessage').className = 'license-message license-valid';
            document.getElementById('licenseMessage').style.display = 'block';
            document.querySelector('.license-section').style.display = 'none';
        } else {
            const licenseMessage = document.getElementById('licenseMessage');
            licenseMessage.innerHTML = 'Support the developer by purchasing a license by contacting <strong> <a href="mailto:idongesit.fpg@gmail.com"> idongesit.fpg@gmail.com  </a></strong> <br><br><br>The license cost only <span style="color:green">$30</span>';
            licenseMessage.className = 'license-message license-invalid';
            licenseMessage.style.display = 'block';
        }
    }
    // Add event listener for license verification
    document.getElementById('verifyLicenseBtn').addEventListener('click', verifyLicenseKey);
    // Also verify on Enter key in license field
    document.getElementById('licenseKey').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            verifyLicenseKey();
        }
    });
    // Check for existing license on page load
    checkExistingLicense();
    // Add license check to premium features
    function checkLicense() {
        return localStorage.getItem('licenseVerified') === 'true';
    }

    function requireLicense() {
        if (!checkLicense()) {
            alert('Please verify your license key first to access this feature.');
            document.querySelector('.license-section').style.display = 'block';
            document.getElementById('licenseKey').focus();
            return false;
        }
        return true;
    }
    // Add a flag to track if we should clear on next focus
    let shouldClearOnNextFocus = false;
    // --- Export Auth Hash & Salt ---
    document.getElementById('exportAuthBtn').addEventListener('click', () => {
        const hash = localStorage.getItem('passwordHash') || '';
        const salt = localStorage.getItem('salt') || '';
        if (!hash && !salt) {
            alert('No authentication data found.');
            return;
        }
        const headers = ['hash', 'salt'];
        const csv = `${headers.join(',')}\n${hash},${salt}`;
        const blob = new Blob([csv], {
            type: 'text/csv;charset=utf-8;'
        });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', 'auth_hash_salt.csv');
        link.click();
    });
    // --- Import and Merge Database CSV ---
    document.getElementById('importCsvBtn').addEventListener('click', async () => {
        const fileInput = document.getElementById('importCsvInput');
        const file = fileInput.files[0];
        if (!file) {
            alert('Please select a CSV file first.');
            return;
        }
        const text = await file.text();
        const rows = text.trim().split(/\r?\n/);
        const headers = rows.shift().split(',');
        if (!db) await initDB();
        const tx = db.transaction(['sites'], 'readwrite');
        const store = tx.objectStore('sites');
        for (const row of rows) {
            const cols = row.split(',').map(c => c.replace(/^"|"$/g, ''));
            const record = {};
            headers.forEach((h, i) => record[h.trim()] = cols[i] || '');
            try {
                store.put(record);
            } catch (e) {
                console.error('Error merging record', e);
            }
        }
        alert('Database merged successfully.');
    });
    // --- IndexedDB SETUP ---
    let db;

    function initDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('passwordManagerDB', 3);
            request.onupgradeneeded = event => {
                db = event.target.result;
                const store = db.createObjectStore('sites', {
                    keyPath: ['url', 'username', 'passwordIndex', 'passwordLength', 'other']
                });
                store.createIndex('url', 'url', {
                    unique: false
                });
            };
            request.onsuccess = event => {
                db = event.target.result;
                resolve(db);
            };
            request.onerror = event => {
                console.error('Database error:', event.target.errorCode);
                reject(event.target.errorCode);
            };
        });
    }
    // Initialize the database when the script loads
    initDB().catch(err => console.error("Failed to initialize DB:", err));
    async function saveSiteData(data) {
        if (!db) await initDB();
        const transaction = db.transaction(['sites'], 'readwrite');
        const store = transaction.objectStore('sites');
        store.put(data);
        return transaction.complete;
    }
    // Function to check if a record already exists
    async function getExistingRecord(siteData) {
        if (!db) await initDB();
        const transaction = db.transaction(['sites'], 'readonly');
        const store = transaction.objectStore('sites');
        const key = [siteData.url, siteData.username, siteData.passwordIndex, siteData.passwordLength, siteData.other];
        return new Promise((resolve, reject) => {
            const request = store.get(key);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }
    // Simple, single unfocus function
    function unfocusActiveInput() {
        if (document.activeElement && document.activeElement.blur) {
            document.activeElement.blur();
        }
    }
    // Clear generated password when any input changes
    ['url', 'username', 'passwordIndex', 'passwordLength', 'other', 'passphrase', 'mnemonic'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', () => {
            const pw = document.getElementById('generatedPassword');
            if (pw) pw.value = '';
            // If user starts typing, don't clear on next focus
            shouldClearOnNextFocus = false;
        });
    });
    // --- Import Auth Hash & Salt CSV ---
    document.getElementById('importAuthCsvBtn').addEventListener('click', async () => {
        const fileInput = document.getElementById('importAuthCsvInput');
        const file = fileInput.files[0];
        if (!file) {
            alert('Please select a CSV file first.');
            return;
        }
        const text = await file.text();
        const rows = text.trim().split(/\r?\n/);
        const headers = rows.shift().split(',');
        if (headers.length !== 2 || headers[0].trim() !== 'hash' || headers[1].trim() !== 'salt') {
            alert('Invalid CSV format. Expected headers: hash,salt');
            return;
        }
        const row = rows[0];
        if (!row) {
            alert('CSV file is empty.');
            return;
        }
        const [hash, salt] = row.split(',').map(c => c.replace(/^"|"$/g, '').trim());
        if (!hash || !salt) {
            alert('Hash or salt is missing in the CSV.');
            return;
        }
        localStorage.setItem('passwordHash', hash);
        localStorage.setItem('salt', salt);
        alert('Hash and salt imported successfully.');
    });
    // --- Toggle BIP39 Login Section ---
    document.getElementById('toggleLoginSection').addEventListener('click', () => {
        const loginSection = document.getElementById('loginSection');
        const toggleBtn = document.getElementById('toggleLoginSection');
        if (loginSection.style.display === 'none') {
            loginSection.style.display = 'block';
            toggleBtn.textContent = 'Hide BIP39 Login';
        } else {
            loginSection.style.display = 'none';
            toggleBtn.textContent = 'Show BIP39 Login';
        }
    });
    // show/hide toggles
    const mnemonicInput = document.getElementById('mnemonic');
    const passInput = document.getElementById('passphrase');
    const toggleMnemonic = document.getElementById('toggleMnemonic');
    const togglePass = document.getElementById('togglePassphrase');
    const cred = {
        mnemonic: "",
        charType: "password"
    }

    function setToggleBehavior(inputEl, btnEl) {
        btnEl.addEventListener('click', () => {
            if (inputEl.type === 'password') {
                inputEl.type = 'text';
                btnEl.textContent = 'Hide';
            } else {
                inputEl.type = 'password';
                btnEl.textContent = 'Show';
            }
            inputEl.focus();
            const val = inputEl.value;
            inputEl.value = '';
            inputEl.value = val;
        });
    }
    setToggleBehavior(mnemonicInput, toggleMnemonic);
    setToggleBehavior(passInput, togglePass);
    // login, PBKDF2, salt management
    const ITER = 100000;
    async function getOrCreateSalt() {
        let s = localStorage.getItem('salt');
        if (s) return s;
        const arr = crypto.getRandomValues(new Uint8Array(16));
        s = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
        localStorage.setItem('salt', s);
        return s;
    }
    async function derivePasswordHash(master) {
        const saltHex = await getOrCreateSalt();
        const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey('raw', enc.encode(master), {
            name: 'PBKDF2'
        }, false, ['deriveBits']);
        const bits = await crypto.subtle.deriveBits({
            name: 'PBKDF2',
            salt,
            iterations: ITER,
            hash: 'SHA-256'
        }, key, 256);
        return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    document.getElementById('loginBtn').addEventListener('click', async () => {
        const mnemonic = mnemonicInput.value.trim();
        const pass = passInput.value || '';
        if (!window.ethers || !window.ethers.Mnemonic) {
            alert('ethers not loaded on window.');
            return;
        }
        try {
            if (!window.ethers.Mnemonic.isValidMnemonic(mnemonic)) {
                alert('Invalid BIP39 mnemonic');
                return;
            }
        } catch (e) {
            if (!window.ethers.utils || !window.ethers.utils.isValidMnemonic || !window.ethers.utils.isValidMnemonic(mnemonic)) {
                alert('Invalid mnemonic (ethers validation unavailable)');
                return;
            }
        }
        const master = mnemonic + pass;
        const hash = await derivePasswordHash(master);
        const stored = localStorage.getItem('passwordHash');
        if (!stored) {
            localStorage.setItem('passwordHash', hash);
            alert('First-time login: stored hash');
        } else if (stored !== hash) {
            alert('Password does not match stored hash');
            return;
        }
        cred.mnemonic = mnemonic;
        document.getElementById('toggleLoginSection').click();
        document.getElementById('fields').style.display = 'block';
    });
    // auto-adjust password length and make readOnly
    let nV = 0;
    document.getElementById('charTypeGroup').addEventListener('change', (e) => {
        const val = e.target.value;
        const len = document.getElementById('passwordLength');
        if (val === 'pin') len.value = 6;
        else len.value = 20;
        len.readOnly = false;
        cred.charType = val;
        document.getElementById('generateBtn').click();
        // Reset clear flag when charType changes
        shouldClearOnNextFocus = false;
    });
    // --- MODIFIED: Get Full Hostname (Keep All Subdomains) ---
    function getSubdomainOrBase(input) {
        try {
            // Add protocol if missing so URL() can parse
            let url = input.trim();
            if (!/^https?:\/\//i.test(url)) {
                url = "https://" + url;
            }
            const {
                hostname
            } = new URL(url.toLowerCase());
            // Return the full hostname (including all subdomains)
            return hostname;
        } catch {
            return ''; // invalid or malformed input
        }
    }
    // Update the generate button handler to properly check database status
    const generateBtnHandler = async () => {
        document.getElementById("savedToDbMessage").style.display = "none";
        let url = (document.getElementById('url').value || '').trim();
        const originalUrl = url;
        const passphrase = (document.getElementById('passphrase').value || '').trim();
        const username = (document.getElementById('username').value || '').trim();
        const passwordIndex = (document.getElementById('passwordIndex').value || '').trim();
        const passwordLength = (document.getElementById('passwordLength').value || '').trim();
        const other = (document.getElementById('other').value || '').trim();
        const typeChecked = document.querySelector('input[name="charType"]:checked');
        if (!url) {
            alert('URL is required.');
            return;
        }
        // Convert URL to full hostname
        url = getSubdomainOrBase(url);
        if (!url) {
            alert('Invalid URL. Please enter a valid domain or URL.');
            return;
        }
        document.getElementById('url').value = url;
        const urlConversionMessage = document.getElementById('urlConversionMessage');
        if (urlConversionMessage) {
            if (originalUrl !== url) {
                urlConversionMessage.textContent = `Converted from ${originalUrl} to ${url}`;
                urlConversionMessage.style.display = 'block';
                setTimeout(() => {
                    urlConversionMessage.classList.add('fade-out');
                    setTimeout(() => {
                        urlConversionMessage.style.display = 'none';
                        urlConversionMessage.classList.remove('fade-out');
                    }, 500);
                }, 3000);
            } else {
                urlConversionMessage.style.display = 'none';
            }
        }
        if (url.includes(' ')) {
            alert('URL cannot contain spaces.');
            return;
        }
        if (!passwordIndex) {
            alert('Password index is required.');
            return;
        }
        if (!typeChecked) {
            alert('Character type must be selected.');
            return;
        }
        if (username.includes(' ')) {
            alert('Username cannot contain spaces.');
            return;
        }
        const lengthNum = parseInt(passwordLength, 10);
        if (isNaN(lengthNum) || lengthNum <= 0 || lengthNum > 86) {
            alert('Password length must be >0 and <=86.');
            return;
        }
        // Reject multiple consecutive spaces
        if (other.includes('  ') || other.includes('	') || other.includes('  ')) {
            alert('The "Other" field cannot contain multiple consecutive spaces (or tabs). Use single spaces only.');
            return;
        }
        // Build array and convert to lowercase
        const otherWords = other ? other.split(' ') : [];
        const dataArray = [passphrase, url, username, passwordIndex, passwordLength, ...otherWords]
            .map(v => String(v).toLowerCase());
        if (window.sortByAscii) {
            const sortedPassphrase = window.sortByAscii(dataArray).join(" ").trim();
            let printableAsciiChars = '';
            for (let i = 32; i <= 126; i++) {
                printableAsciiChars += String.fromCharCode(i);
            }
            const charsetMap = {
                password: 62,
                pin: 10,
                ascii: printableAsciiChars
            }
            const passwordType = typeChecked.value;
            const password = await window.buildPassword(cred.mnemonic, sortedPassphrase, parseInt(passwordLength), charsetMap[passwordType]);
            // Show the generated password
            const resultContainer = document.getElementById('passwordResultContainer');
            const passwordField = document.getElementById('generatedPassword');
            passwordField.value = password;
            passwordField.type = 'password';
            document.getElementById('showHideBtn').textContent = 'Show';
            resultContainer.style.display = 'block';
            document.getElementById('showHideBtn').click(); // Make password visible
            // Check if the password data exists in the database with the SAME charType
            if (!db) await initDB();
            const transaction = db.transaction(['sites'], 'readonly');
            const store = transaction.objectStore('sites');
            const key = [url, username, passwordIndex, passwordLength, other];
            const request = store.get(key);
            request.onsuccess = () => {
                const notInDbMessage = document.getElementById('notInDbMessage');
                const savedToDbMessage = document.getElementById('savedToDbMessage');
                if (!request.result) {
                    // No record exists
                    notInDbMessage.style.display = 'block';
                    savedToDbMessage.style.display = 'none';
                } else if (request.result.charType !== passwordType) {
                    // Record exists but charType is different
                    notInDbMessage.style.display = 'block';
                    savedToDbMessage.style.display = 'none';
                } else {
                    // Record exists with same charType
                    notInDbMessage.style.display = 'none';
                    savedToDbMessage.style.display = 'none';
                }
            };
            request.onerror = (event) => {
                console.error('Error checking database:', event.target.error);
                document.getElementById('notInDbMessage').style.display = 'block';
            };
        } else {
            console.error('sortByAscii not found on window');
        }
    }
    document.getElementById('generateBtn').addEventListener('click', generateBtnHandler);
    // Update the copy button handler to only save when necessary
    document.getElementById('copyBtn').addEventListener('click', async () => {
        const passwordField = document.getElementById('generatedPassword');
        if (passwordField.value) {
            navigator.clipboard.writeText(passwordField.value).then(async () => {
                const btn = document.getElementById('copyBtn');
                btn.textContent = 'Copied!  ✅✅';
                // Set flag to clear on next focus
                shouldClearOnNextFocus = true;
                // Unfocus ONLY after successful copy
                setTimeout(() => {
                    unfocusActiveInput();
                }, 100);
                setTimeout(() => {
                    btn.textContent = 'Copy';
                }, 3000);
                // Prepare site data
                const siteData = {
                    url: (document.getElementById('url').value || '').trim(),
                    username: (document.getElementById('username').value || '').trim(),
                    passwordIndex: (document.getElementById('passwordIndex').value || '').trim(),
                    passwordLength: (document.getElementById('passwordLength').value || '').trim(),
                    other: (document.getElementById('other').value || '').trim(),
                    charType: document.querySelector('input[name="charType"]:checked').value,
                    createdAt: new Date().toISOString()
                };
                if (siteData.url && siteData.passwordIndex) {
                    try {
                        // Check if record already exists with the same composite key
                        const existingRecord = await getExistingRecord(siteData);
                        if (!existingRecord) {
                            // New record - save it
                            await saveSiteData(siteData);
                            document.getElementById('savedToDbMessage').style.display = 'block';
                            setTimeout(() => {
                                document.getElementById('savedToDbMessage').style.display = 'none';
                            }, 3000);
                        } else if (existingRecord.charType !== siteData.charType) {
                            // Only update if charType changed
                            await saveSiteData(siteData);
                            document.getElementById('savedToDbMessage').style.display = 'block';
                            setTimeout(() => {
                                document.getElementById('savedToDbMessage').style.display = 'none';
                            }, 3000);
                        }
                        // If record exists and charType is the same, do nothing
                    } catch (err) {
                        console.error('Failed to check/save site data:', err);
                    }
                }
            }).catch(err => {
                console.error('Failed to copy text: ', err);
                alert('Could not copy password.');
            });
        }
    });
    // Handler for the show/hide button
    document.getElementById('showHideBtn').addEventListener('click', () => {
        const passwordField = document.getElementById('generatedPassword');
        const btn = document.getElementById('showHideBtn');
        if (passwordField.type === 'password') {
            passwordField.type = 'text';
            btn.textContent = 'Hide';
        } else {
            passwordField.type = 'password';
            btn.textContent = 'Show';
        }
    });
    // --- Fixed typo in 'separator' ---
    function getLastWord(word, separator = " ") {
        word = word.split(separator);
        return word[word.length - 1]; //return last word
    }

    function suggestWords(term, n = 12, wl = window.wordlist, callback = getLastWord) {
        if (callback) term = callback(term);
        if (!term) return [];
        term = term.split("");
        let stringReg = "^";
        stringReg += (term.map(letter => letter += ".*").join(""));
        const regex = new RegExp(stringReg, "gim");
        return wl.reduce((acc, w) => {
            const match = w.match(regex);
            if (match && match.length && match[0].length) {
                acc.push(w);
            }
            return acc;
        }, []);
    }
    // Create and style a suggestion box for Mnemonic
    const mnemonicSuggestionBox = document.createElement("div");
    mnemonicSuggestionBox.style.position = "absolute";
    mnemonicSuggestionBox.style.background = "#fff";
    mnemonicSuggestionBox.style.border = "1px solid #ccc";
    mnemonicSuggestionBox.style.borderRadius = "6px";
    mnemonicSuggestionBox.style.boxShadow = "0 2px 8px rgba(0,0,0,0.1)";
    mnemonicSuggestionBox.style.zIndex = "1000";
    mnemonicSuggestionBox.style.width = mnemonicInput.offsetWidth + "px";
    mnemonicSuggestionBox.style.display = "none";
    mnemonicSuggestionBox.style.maxHeight = "150px";
    mnemonicSuggestionBox.style.overflowY = "auto";
    mnemonicInput.parentNode.appendChild(mnemonicSuggestionBox);
    // Function to show Mnemonic suggestions
    function showMnemonicSuggestions(suggestions) {
        mnemonicSuggestionBox.innerHTML = "";
        if (suggestions.length === 0) {
            mnemonicSuggestionBox.style.display = "none";
            return;
        }
        suggestions.forEach(s => {
            const div = document.createElement("div");
            div.textContent = s;
            div.style.padding = "6px 10px";
            div.style.cursor = "pointer";
            div.addEventListener("mouseover", () => div.style.background = "#eef2ff");
            div.addEventListener("mouseout", () => div.style.background = "#fff");
            div.addEventListener("click", () => {
                const words = mnemonicInput.value.trim().split(/\s+/);
                words[words.length - 1] = s; // replace last word
                mnemonicInput.value = words.join(" ") + " ";
                mnemonicSuggestionBox.style.display = "none";
                mnemonicInput.focus();
            });
            mnemonicSuggestionBox.appendChild(div);
        });
        mnemonicSuggestionBox.style.display = "block";
    }
    // Handle input events on mnemonic field
    mnemonicInput.addEventListener("input", (e) => {
        const value = e.target.value.trim().toLowerCase();
        if (!value) {
            mnemonicSuggestionBox.style.display = "none";
            return;
        }
        const suggestions = suggestWords(value);
        showMnemonicSuggestions(suggestions);
    });
    // --- URL Suggestions Logic ---
    const urlInput = document.getElementById('url');
    const urlSuggestionBox = document.createElement("div");
    urlSuggestionBox.style.position = "absolute";
    urlSuggestionBox.style.background = "#fff";
    urlSuggestionBox.style.border = "1px solid #ccc";
    urlSuggestionBox.style.borderRadius = "6px";
    urlSuggestionBox.style.boxShadow = "0 2px 8px rgba(0,0,0,0.1)";
    urlSuggestionBox.style.zIndex = "1000";
    urlSuggestionBox.style.width = urlInput.offsetWidth + "px";
    urlSuggestionBox.style.display = "none";
    urlSuggestionBox.style.maxHeight = "150px";
    urlSuggestionBox.style.overflowY = "auto";
    urlInput.parentNode.insertBefore(urlSuggestionBox, urlInput.nextSibling);
    // --- NEW: Track input method for URL ---
    let lastUrlInputMethod = 'typed'; // 'typed' or 'pasted'
    // --- NEW: Detect paste events ---
    function detectPaste(event) {
        // Simple detection - if input value changed significantly in one event, it was likely pasted
        const input = event.target;
        const previousValue = input.getAttribute('data-prev-value') || '';
        const currentValue = input.value;
        input.setAttribute('data-prev-value', currentValue);
        return currentValue.length - previousValue.length > 3; // If more than 3 chars added at once, assume paste
    }
    // --- NEW: Find perfect match function ---
    function findPerfectMatch(suggestions, searchTerm) {
        if (!suggestions || suggestions.length === 0) return null;
        const topSuggestion = suggestions[0];
        const searchTermLower = searchTerm.toLowerCase();
        // Check if top suggestion has perfect score and exact URL match
        if (topSuggestion.score >= 100 &&
            topSuggestion.url?.toLowerCase() === searchTermLower) {
            return topSuggestion;
        }
        return null;
    }
    // --- NEW: Function to show auto-selection feedback ---
    function showAutoSelectFeedback(url) {
        // Create or use existing conversion message element
        const feedbackElement = document.getElementById('urlConversionMessage');
        if (feedbackElement) {
            feedbackElement.textContent = `Auto-selected: ${url}`;
            feedbackElement.style.display = 'block';
            feedbackElement.style.color = '#059669'; // Green color for success
            feedbackElement.style.background = '#f0fdf4';
            // Add fade-out effect after 2 seconds
            setTimeout(() => {
                feedbackElement.classList.add('fade-out');
                setTimeout(() => {
                    feedbackElement.style.display = 'none';
                    feedbackElement.classList.remove('fade-out');
                    // Reset to original style
                    feedbackElement.style.color = '';
                    feedbackElement.style.background = '';
                }, 500);
            }, 2000);
        }
    }
    // --- UPDATED: Enhanced handleSuggestionClick function ---
    async function handleSuggestionClick(s) {
        try {
            if (!db) await initDB();
            const tx = db.transaction(["sites"], "readonly");
            const store = tx.objectStore("sites");
            const key = [s.url, s.username, s.passwordIndex, s.passwordLength, s.other];
            const req = store.get(key);
            req.onsuccess = async e => {
                const data = e.target.result;
                if (!data) return;
                // Populate all corresponding input fields
                document.getElementById("url").value = data.url || "";
                document.getElementById("username").value = data.username || "";
                document.getElementById("passwordIndex").value = data.passwordIndex || "";
                document.getElementById("passwordLength").value = data.passwordLength || "";
                document.getElementById("other").value = data.other || "";
                // Set the correct radio button for charType
                const charTypeRadio = document.querySelector(`input[name='charType'][value='${data.charType}']`);
                if (charTypeRadio) {
                    charTypeRadio.checked = true;
                }
                // Hide conversion message when selecting a suggestion
                const urlConversionMessage = document.getElementById('urlConversionMessage');
                if (urlConversionMessage) urlConversionMessage.style.display = 'none';
                // Hide suggestion box
                urlSuggestionBox.style.display = "none";
                // Trigger password generation
                await generateBtnHandler();
                // Set flag for auto-selected items too
                shouldClearOnNextFocus = true;
                // Automatically copy the generated password (this will handle unfocusing)
                document.getElementById('copyBtn').click();
                // Show brief feedback that auto-selection occurred
                showAutoSelectFeedback(s.url);
            };
            req.onerror = e => {
                console.error("Error fetching record:", e.target.error);
            };
        } catch (err) {
            console.error("Error fetching record:", err);
        }
    }
    // --- UPDATED: Enhanced getSiteSuggestions function ---
    async function getSiteSuggestions(term, inputMethod = lastUrlInputMethod) {
        if (!db || !term) return [];
        const transaction = db.transaction(['sites'], 'readonly');
        const store = transaction.objectStore('sites');
        return new Promise((resolve, reject) => {
            const request = store.getAll();
            request.onsuccess = () => {
                const allRecords = request.result;
                // Get normalized version of the search term
                const normalizedTerm = getSubdomainOrBase(term) || term.toLowerCase();
                const originalTerm = term.toLowerCase();
                // If input was pasted, we can be more confident in normalization
                const searchTerms = inputMethod === 'pasted' && normalizedTerm !== originalTerm ? [normalizedTerm] : // Prefer normalized for pasted content
                    [originalTerm, normalizedTerm]; // Search both for typed content
                // Score and rank the results
                const scoredResults = allRecords.map(record => {
                    let score = 0;
                    const recordUrl = record.url?.toLowerCase() || '';
                    const recordUsername = record.username?.toLowerCase() || '';
                    // Find the best match across all search terms
                    let bestScoreForRecord = 0;
                    searchTerms.forEach(searchTerm => {
                        if (!searchTerm) return;
                        let termScore = 0;
                        // EXACT MATCH - Perfect score (this triggers auto-selection)
                        if (recordUrl === searchTerm) {
                            termScore += 200; // Very high score for exact match
                        }
                        // Starts with search term
                        else if (recordUrl.startsWith(searchTerm)) {
                            termScore += 50;
                        }
                        // Contains search term anywhere
                        else if (recordUrl.includes(searchTerm)) {
                            termScore += 20;
                        }
                        // Domain/subdomain matching logic
                        if (searchTerm.includes('.')) {
                            const searchParts = searchTerm.split('.');
                            const urlParts = recordUrl.split('.');
                            // Exact domain match (including subdomains)
                            if (recordUrl === searchTerm) {
                                termScore += 30; // Already covered above, but for clarity
                            }
                            // Same top-level domain
                            if (searchParts.length > 0 && urlParts.length > 0 &&
                                searchParts[searchParts.length - 1] === urlParts[urlParts.length - 1]) {
                                termScore += 10;
                            }
                            // Same second-level domain
                            if (searchParts.length >= 2 && urlParts.length >= 2 &&
                                searchParts[searchParts.length - 2] === urlParts[urlParts.length - 2]) {
                                termScore += 15;
                            }
                        }
                        // Username matches (bonus points)
                        if (recordUsername && searchTerm && recordUsername.includes(searchTerm)) {
                            termScore += 5;
                        }
                        // Boost score if this is the normalized term and input was pasted
                        if (searchTerm === normalizedTerm && inputMethod === 'pasted') {
                            termScore += 15;
                        }
                        // Update best score for this record
                        bestScoreForRecord = Math.max(bestScoreForRecord, termScore);
                    });
                    score = bestScoreForRecord;
                    // Recent entries get slight boost
                    if (record.createdAt) {
                        const recordDate = new Date(record.createdAt);
                        const daysAgo = (new Date() - recordDate) / (1000 * 60 * 60 * 24);
                        if (daysAgo < 7) {
                            score += 5; // Very recent (last week)
                        } else if (daysAgo < 30) {
                            score += 2; // Recent (last month)
                        }
                    }
                    return {
                        ...record,
                        score
                    };
                });
                // Filter out zero-score results and sort by score (descending)
                const filteredResults = scoredResults
                    .filter(item => item.score > 0)
                    .sort((a, b) => b.score - a.score);
                // Remove duplicates
                const seen = new Set();
                const uniqueResults = filteredResults.filter(item => {
                    const key = `${item.url}|${item.username}|${item.passwordIndex}|${item.passwordLength}|${item.other}`;
                    if (seen.has(key)) {
                        return false;
                    }
                    seen.add(key);
                    return true;
                });
                resolve(uniqueResults.slice(0, 20));
            };
            request.onerror = (event) => {
                console.error('Error fetching site suggestions:', event.target.error);
                reject(event.target.error);
            };
        });
    }
    // --- UPDATED: Enhanced showSiteSuggestions function ---
    async function showSiteSuggestions(suggestions, inputMethod = 'typed') {
        urlSuggestionBox.innerHTML = "";
        suggestions = suggestions.filter(s => typeof s === "object" && s.url);
        if (suggestions.length === 0) {
            urlSuggestionBox.style.display = "none";
            return;
        }
        suggestions.forEach(s => {
            let shortUser = s.username || "";
            if (shortUser.length > 5) shortUser = shortUser.substring(0, 5) + "...";
            const displayText = `${s.url} — ${shortUser || "(no user)"} — index: ${s.passwordIndex}`;
            const div = document.createElement("div");
            div.textContent = displayText;
            div.style.padding = "6px 10px";
            div.style.cursor = "pointer";
            // Highlight perfect matches
            if (s.score >= 100) {
                div.style.background = "#f0fdf4";
                div.style.borderLeft = "3px solid #059669";
            }
            div.addEventListener("mouseover", () => {
                if (s.score < 100) { // Only change background if not already highlighted
                    div.style.background = "#eef2ff";
                }
            });
            div.addEventListener("mouseout", () => {
                if (s.score < 100) {
                    div.style.background = "#fff";
                } else {
                    div.style.background = "#f0fdf4";
                }
            });
            div.addEventListener("click", async () => {
                await handleSuggestionClick(s);
            });
            urlSuggestionBox.appendChild(div);
        });
        const wrapper = urlInput.closest(".password-wrapper");
        if (wrapper) {
            wrapper.style.position = "relative";
            wrapper.style.overflow = "visible";
        }
        const inputRect = urlInput.getBoundingClientRect();
        // Adjust suggestion box position to avoid overlap with conversion message
        const urlConversionMessage = document.getElementById('urlConversionMessage');
        const offset = urlConversionMessage && urlConversionMessage.style.display === 'block' ? urlConversionMessage.offsetHeight + 5 : 0;
        urlSuggestionBox.style.position = "absolute";
        urlSuggestionBox.style.top = `${inputRect.bottom + window.scrollY + offset}px`;
        urlSuggestionBox.style.left = `${inputRect.left + window.scrollX}px`;
        urlSuggestionBox.style.width = `${urlInput.offsetWidth}px`;
        urlSuggestionBox.style.display = "block";
    }
    // --- UPDATED: Enhanced URL input event listener with auto-selection ---
    urlInput.addEventListener("input", async (e) => {
        const value = e.target.value.trim();
        // Detect if this was a paste operation
        const wasPasted = detectPaste(e);
        lastUrlInputMethod = wasPasted ? 'pasted' : 'typed';
        // Clear previous state
        urlSuggestionBox.style.display = "none";
        const urlConversionMessage = document.getElementById('urlConversionMessage');
        if (urlConversionMessage) {
            urlConversionMessage.style.display = 'none';
        }
        // Clear generated password
        const pw = document.getElementById('generatedPassword');
        if (pw) pw.value = '';
        if (!value) {
            return;
        }
        // If user pasted, we can be more aggressive with normalization
        if (wasPasted) {
            const normalizedUrl = getSubdomainOrBase(value);
            const finalUrl = normalizedUrl || value;
            // Update the field with normalized URL if it changed
            if (normalizedUrl && normalizedUrl !== value) {
                urlInput.value = normalizedUrl;
                // Show conversion message
                if (urlConversionMessage) {
                    urlConversionMessage.textContent = `Converted from ${value} to ${normalizedUrl}`;
                    urlConversionMessage.style.display = 'block';
                    // Add fade-out effect after 3 seconds
                    setTimeout(() => {
                        urlConversionMessage.classList.add('fade-out');
                        setTimeout(() => {
                            urlConversionMessage.style.display = 'none';
                            urlConversionMessage.classList.remove('fade-out');
                        }, 500);
                    }, 3000);
                }
            }
            // Get suggestions for the normalized URL
            const suggestions = await getSiteSuggestions(finalUrl, 'pasted');
            // Check for 100% match (exact URL match with highest score)
            const perfectMatch = findPerfectMatch(suggestions, finalUrl);
            if (perfectMatch) {
                // Auto-select the perfect match
                await handleSuggestionClick(perfectMatch);
                return;
            }
            // No perfect match, show suggestions as usual
            showSiteSuggestions(suggestions, 'pasted');
            return;
        }
        // For typed input
        const suggestions = await getSiteSuggestions(value, 'typed');
        showSiteSuggestions(suggestions, 'typed');
    });
    // Add focus event listener to URL input to clear fields when focused after copy
    urlInput.addEventListener('focus', () => {
        if (shouldClearOnNextFocus) {
            // Clear URL and username fields
            urlInput.value = '';
            document.getElementById('username').value = '';
            // Also clear the generated password and messages
            const passwordField = document.getElementById('generatedPassword');
            if (passwordField) passwordField.value = '';
            document.getElementById('notInDbMessage').style.display = 'none';
            document.getElementById('savedToDbMessage').style.display = 'none';
            // Hide password result container
            document.getElementById('passwordResultContainer').style.display = 'none';
            // Reset the flag so it only happens once
            shouldClearOnNextFocus = false;
            // Hide any URL conversion message
            const urlConversionMessage = document.getElementById('urlConversionMessage');
            if (urlConversionMessage) {
                urlConversionMessage.style.display = 'none';
            }
        }
    });
    // Reset flag when password index changes (common action after copy)
    document.getElementById('passwordIndex').addEventListener('change', () => {
        shouldClearOnNextFocus = false;
    });
    // Hide suggestions when clicking elsewhere
    document.addEventListener("click", (e) => {
        if (!mnemonicInput.contains(e.target) && !mnemonicSuggestionBox.contains(e.target)) {
            mnemonicSuggestionBox.style.display = "none";
        }
        if (!urlInput.contains(e.target) && !urlSuggestionBox.contains(e.target)) {
            urlSuggestionBox.style.display = "none";
        }
    });
    // Handler for the clear button
    document.getElementById('clearHashBtn').addEventListener('click', () => {
        if (confirm('Are you sure you want to clear the stored password hash and salt? This will require you to re-initialize on your next login.')) {
            localStorage.removeItem('passwordHash');
            localStorage.removeItem('salt');
            alert('Stored data has been cleared.');
        }
    });
    // --- Export to CSV Button Handler ---
    document.getElementById('exportCsvBtn').addEventListener('click', async () => {
        if (!db) await initDB();
        const transaction = db.transaction(['sites'], 'readonly');
        const store = transaction.objectStore('sites');
        const allRecordsRequest = store.getAll();
        allRecordsRequest.onsuccess = () => {
            const records = allRecordsRequest.result;
            if (records.length === 0) {
                alert('No data to export.');
                return;
            }
            const headers = ['url', 'username', 'passwordIndex', 'passwordLength', 'other', 'charType', 'createdAt'];
            let csvContent = headers.join(',') + '\n';
            records.forEach(record => {
                const row = headers.map(header => {
                    let value = record[header] || '';
                    if (typeof value === 'string' && value.includes(',')) {
                        return `"${value}"`;
                    }
                    return value;
                });
                csvContent += row.join(',') + '\n';
            });
            const blob = new Blob([csvContent], {
                type: 'text/csv;charset=utf-8;'
            });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', 'bip39_logins.csv');
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        };
        allRecordsRequest.onerror = (event) => {
            console.error('Error fetching data for export:', event.target.error);
            alert('Could not export data.');
        };
    });
}); // End of DOMContentLoaded