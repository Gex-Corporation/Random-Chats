const firebaseConfig = {
            apiKey: "AIzaSyCng8ZDKd6zOc2ydbf-wUljOzEAViWSOQI",
            authDomain: "computer-kaaj.firebaseapp.com",
            projectId: "computer-kaaj",
            storageBucket: "computer-kaaj.firebasestorage.app",
            messagingSenderId: "786670596427",
            appId: "1:786670596427:web:db95ddef44d9f35739f8ce",
            measurementId: "G-007FD30DQ6"
        };

        firebase.initializeApp(firebaseConfig);
        const db = firebase.firestore();

        let currentUserId = null;
        let myGroups = [];
        let unsubscribeGroups = null;
        let myProfile = null;
        let selectedGender = 'male';
        let isSignupMode = false;
        let unsubscribeProfile = null;

        // à¦•à§à¦°à¦¿à¦ªà§à¦Ÿà§‹, MQTT à¦“ à¦ªà§à¦°à§‡à¦œà§‡à¦¨à§à¦¸ à¦¸à§à¦Ÿà§‡à¦Ÿ
        let client = null;
        let activeFriendUid = null;
        let myPrivKeyObj = null;
        const aesKeyCache = new Map();
        const pendingAckTimers = new Map();
        const userStatusMap = new Map(); // UID -> 'online' | 'offline'

        // ========== Firebase Read Optimization Cache ==========
        let allUsersCache = null;       // loadAllUsers cache
        let allUsersCacheTime = 0;      // cache timestamp
        const ALL_USERS_CACHE_TTL = 5 * 60 * 1000; // 5 à¦®à¦¿à¦¨à¦¿à¦Ÿ
        let liveChannelsCache = null;   // loadLiveChannels cache (session-long)
        // =======================================================

        const flags = {
            "Bangladesh": "🇧🇩", "India": "🇮🇳", "United States": "🇺🇸",
            "Australia": "🇦🇺", "Canada": "🇨🇦", "Germany": "🇩🇪",
            "Malaysia": "🇲🇾", "Pakistan": "🇵🇰", "Saudi Arabia": "🇸🇦",
            "Singapore": "🇸🇬", "United Arab Emirates": "🇦🇪",
            "United Kingdom": "🇬🇧", "Other": "ðŸŒ"
        };

        // --- à¦•à§à¦°à¦¿à¦ªà§à¦Ÿà§‹à¦—à§à¦°à¦¾à¦«à¦¿ à¦‡à¦žà§à¦œà¦¿à¦¨ (ECDH + AES-256 GCM) ---
        function buf2b64(buf) {
            let bin = '';
            const b = new Uint8Array(buf);
            for (let i = 0; i < b.byteLength; i++) {
                bin += String.fromCharCode(b[i]);
            }
            return btoa(bin);
        }

        function b642buf(b64) {
            const bin = atob(b64);
            const b = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) {
                b[i] = bin.charCodeAt(i);
            }
            return b.buffer;
        }

        // --- E2EE Private Key Protection (PBKDF2 + AES-GCM) ---
        async function deriveAESKeyFromPassword(password, saltUid) {
            const enc = new TextEncoder();
            const keyMaterial = await window.crypto.subtle.importKey(
                "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
            );
            return await window.crypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt: enc.encode(saltUid),
                    iterations: 100000,
                    hash: "SHA-256"
                },
                keyMaterial,
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );
        }

        async function encryptPrivateKey(jwkString, password, uid) {
            const aesKey = await deriveAESKeyFromPassword(password, uid);
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const cipher = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv }, aesKey, new TextEncoder().encode(jwkString)
            );
            return { encryptedData: buf2b64(cipher), iv: buf2b64(iv) };
        }

        async function decryptPrivateKey(encryptedData, ivB64, password, uid) {
            const aesKey = await deriveAESKeyFromPassword(password, uid);
            const iv = new Uint8Array(b642buf(ivB64));
            const dataBuf = b642buf(encryptedData);
            try {
                const dec = await window.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv }, aesKey, dataBuf
                );
                return new TextDecoder().decode(dec);
            } catch (e) {
                throw new Error("Incorrect Password or Corrupted Key");
            }
        }

        async function initOrLoadKeys(uid) {
            const privStored = localStorage.getItem('ghost_priv_key_' + uid);
            const pubStored = localStorage.getItem('ghost_pub_key_' + uid);

            if (privStored && pubStored) {
                try {
                    const privJwk = JSON.parse(privStored);
                    myPrivKeyObj = await window.crypto.subtle.importKey(
                        "jwk", privJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]
                    );
                    return JSON.parse(pubStored);
                } catch (e) {
                    console.warn("à¦•à§à¦°à¦¿à¦ªà§à¦Ÿà§‹ à¦šà¦¾à¦¬à¦¿ à¦°à¦¿à¦•à¦­à¦¾à¦°à¦¿ à¦¬à§à¦¯à¦°à§à¦¥, à¦¨à¦¤à§à¦¨ à¦¤à§ˆà¦°à¦¿ à¦¹à¦šà§à¦›à§‡...", e);
                }
            }

            const keyPair = await window.crypto.subtle.generateKey(
                { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]
            );
            const exportedPub = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
            const exportedPriv = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

            localStorage.setItem('ghost_priv_key_' + uid, JSON.stringify(exportedPriv));
            localStorage.setItem('ghost_pub_key_' + uid, JSON.stringify(exportedPub));

            myPrivKeyObj = keyPair.privateKey;
            return exportedPub;
        }

        async function computeAESKeyWith(peerPublicKeyJwk) {
            if (!peerPublicKeyJwk || !peerPublicKeyJwk.x || !peerPublicKeyJwk.y) {
                throw new Error("Invalid Public Key Data");
            }
            const cleanJwk = {
                kty: "EC",
                crv: peerPublicKeyJwk.crv || "P-256",
                x: peerPublicKeyJwk.x,
                y: peerPublicKeyJwk.y,
                ext: true
            };
            const peerKey = await window.crypto.subtle.importKey(
                "jwk", cleanJwk, { name: "ECDH", namedCurve: "P-256" }, true, []
            );
            return await window.crypto.subtle.deriveKey(
                { name: "ECDH", public: peerKey },
                myPrivKeyObj,
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt", "decrypt"]
            );
        }

        async function encryptPayload(text, aesKey) {
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const cipher = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv }, aesKey, new TextEncoder().encode(text)
            );
            return { iv: buf2b64(iv), data: buf2b64(cipher) };
        }

        async function decryptPayload(encrypted, aesKey) {
            const iv = new Uint8Array(b642buf(encrypted.iv));
            const dataBuf = b642buf(encrypted.data);
            const dec = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv }, aesKey, dataBuf
            );
            return new TextDecoder().decode(dec);
        }

        // --- à§ªà§® à¦˜à¦£à§à¦Ÿà¦¾à¦° à¦•à§à¦²à¦¿à¦¨à¦†à¦ª à¦«à¦¿à¦²à§à¦Ÿà¦¾à¦° à¦“ à¦²à§‹à¦•à¦¾à¦² à¦¸à§à¦Ÿà§‹à¦°à§‡à¦œ ---
        function purgeExpiredMessages() {
            const now = Date.now();
            const FORTY_EIGHT_HOURS = 48 * 60 * 60 * 1000;

            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && (key.startsWith(`ghost_msgs_${currentUserId}_`) || key.startsWith(`ghost_group_msgs_${currentUserId}_`))) {
                    try {
                        let list = JSON.parse(localStorage.getItem(key)) || [];
                        const fresh = list.filter(m => (now - m.timestamp) < FORTY_EIGHT_HOURS);
                        if (fresh.length !== list.length) {
                            localStorage.setItem(key, JSON.stringify(fresh));
                        }
                    } catch (e) { }
                }
            }
        }

        function getLocalChat(friendUid) {
            purgeExpiredMessages();
            const key = `ghost_msgs_${currentUserId}_${friendUid}`;
            try {
                return JSON.parse(localStorage.getItem(key)) || [];
            } catch (e) { return []; }
        }

        function getLocalGroupChat(groupId) {
            const key = `ghost_group_msgs_${currentUserId}_${groupId}`;
            try {
                return JSON.parse(sessionStorage.getItem(key)) || [];
            } catch (e) { return []; }
        }

        function saveMessageLocally(friendUid, msgObj) {
            const key = `ghost_msgs_${currentUserId}_${friendUid}`;
            const list = getLocalChat(friendUid);
            if (!list.some(m => m.id === msgObj.id)) {
                list.push(msgObj);
                try {
                    localStorage.setItem(key, JSON.stringify(list));
                } catch (e) { console.error("LocalStorage full!", e); }
            }
        }

        function saveGroupMessageLocally(groupId, msgObj) {
            const key = `ghost_group_msgs_${currentUserId}_${groupId}`;
            const list = getLocalGroupChat(groupId);
            if (!list.some(m => m.id === msgObj.id)) {
                list.push(msgObj);
                try {
                    sessionStorage.setItem(key, JSON.stringify(list));
                } catch (e) { console.error("SessionStorage full!", e); }
            }
        }

        function markChatAsRead(friendUid) {
            const key = `ghost_msgs_${currentUserId}_${friendUid}`;
            const list = getLocalChat(friendUid);
            let changed = false;
            list.forEach(m => {
                if (m.unread) { m.unread = false; changed = true; }
            });
            if (changed) localStorage.setItem(key, JSON.stringify(list));
            updateUnreadBadges();
            
            if (client && client.connected) {
                client.publish('ghostchat/user/' + friendUid, JSON.stringify({
                    type: 'msg_seen',
                    fromUid: currentUserId,
                    toUid: friendUid
                }));
            }
        }

        function markGroupChatAsRead(groupId) {
            const key = `ghost_group_msgs_${currentUserId}_${groupId}`;
            const list = getLocalGroupChat(groupId);
            let changed = false;
            list.forEach(m => {
                if (m.unread) { m.unread = false; changed = true; }
            });
            if (changed) localStorage.setItem(key, JSON.stringify(list));
            updateUnreadBadges();
        }

        function getUnreadCount(friendUid) {
            const list = getLocalChat(friendUid);
            return list.filter(m => m.unread && m.sender !== currentUserId).length;
        }

        function getGroupUnreadCount(groupId) {
            const list = getLocalGroupChat(groupId);
            return list.filter(m => m.unread && m.sender !== currentUserId).length;
        }

        function updateUnreadBadges() {
            if (!myProfile || !myProfile.friends) return;

            let totalUnread = 0;

            myProfile.friends.forEach(f => {
                const count = getUnreadCount(f.uid);
                totalUnread += count;
                const badge = document.getElementById(`unread_badge_${f.uid}`);
                if (badge) {
                    if (count > 0) {
                        badge.textContent = `🔴 ${count}`;
                        badge.style.display = 'inline-block';
                    } else {
                        badge.style.display = 'none';
                    }
                }
            });

            const navChatsBtn = document.getElementById('navChatsBtn');
            if (navChatsBtn) {
                if (totalUnread > 0) {
                    navChatsBtn.style.color = 'var(--danger)';
                } else {
                    navChatsBtn.style.color = '';
                }
            }

            if (document.getElementById('tabChats').classList.contains('active')) {
                renderChatsTab();
            }
        }

        // --- Offline à¦®à§‡à¦‡à¦²à¦¬à¦•à§à¦¸ à¦¸à¦¿à¦™à§à¦• (à¦«à¦¾à§Ÿà¦¾à¦°à¦¬à§‡à¦¸ à¦¬à§à¦¯à¦¾à¦•à¦†à¦ª à¦‰à¦¦à§à¦§à¦¾à¦°) ---
        async function syncOfflineMailbox() {
            if (!currentUserId) return;
            try {
                const mailboxRef = db.collection('mailboxes').doc(currentUserId);
                const doc = await mailboxRef.get();

                if (doc.exists && doc.data().messages && doc.data().messages.length > 0) {
                    const messages = doc.data().messages;

                    for (const m of messages) {
                        let aesKey = aesKeyCache.get(m.sender);
                        if (!aesKey) {
                            const senderDoc = await db.collection('users').doc(m.sender).get();
                            if (senderDoc.exists && senderDoc.data().publicKey) {
                                aesKey = await computeAESKeyWith(senderDoc.data().publicKey);
                                aesKeyCache.set(m.sender, aesKey);
                            }
                        }

                        if (aesKey) {
                            try {
                                const plainText = await decryptPayload(m.payload, aesKey);

                                if (m.type === 'group_chat') {
                                    saveGroupMessageLocally(m.groupId, {
                                        id: m.id,
                                        sender: m.sender,
                                        text: plainText,
                                        timestamp: m.timestamp || Date.now(),
                                        status: 'delivered',
                                        unread: (activeGroupId !== m.groupId),
                                        senderName: m.senderName
                                    });
                                    if (activeGroupId === m.groupId) {
                                        renderLocalGroupChat(m.groupId);
                                    }
                                } else {
                                    saveMessageLocally(m.sender, {
                                        id: m.id,
                                        sender: m.sender,
                                        text: plainText,
                                        timestamp: m.timestamp || Date.now(),
                                        status: 'delivered',
                                        unread: (activeFriendUid !== m.sender)
                                    });

                                    if (client && client.connected) {
                                        client.publish('ghostchat/user/' + m.sender, JSON.stringify({
                                            type: 'msg_ack',
                                            msgId: m.id,
                                            fromUid: currentUserId,
                                            toUid: m.sender
                                        }));
                                    }

                                    if (activeFriendUid === m.sender) {
                                        renderLocalChat(m.sender);
                                        if (client && client.connected) {
                                            client.publish('ghostchat/user/' + m.sender, JSON.stringify({
                                                type: 'msg_seen',
                                                fromUid: currentUserId,
                                                toUid: m.sender
                                            }));
                                        }
                                    }
                                }
                            } catch (err) { console.error("à¦®à§‡à¦‡à¦²à¦¬à¦•à§à¦¸ à¦¡à¦¿à¦•à§à¦°à¦¿à¦ªà¦¶à¦¨ à¦¬à§à¦¯à¦°à§à¦¥:", err); }
                        }
                    }

                    await mailboxRef.delete();
                    updateUnreadBadges();
                }
            } catch (e) { console.error("à¦®à§‡à¦‡à¦²à¦¬à¦•à§à¦¸ à¦¸à¦¿à¦™à§à¦• à¦¬à§à¦¯à¦°à§à¦¥:", e); }
        }

        function showScreen(screenId) {
            document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
            document.getElementById(screenId).classList.add('active');
        }

        // --- à¦•à¦¾à¦¸à§à¦Ÿà¦® Registration à¦“ Login ---
        function selectGender(g) {
            selectedGender = g;
            document.getElementById('gMale').className = 'gender-btn ' + (g === 'male' ? 'selected' : '');
            document.getElementById('gFemale').className = 'gender-btn ' + (g === 'female' ? 'selected' : '');
        }

        const authSwitch = document.getElementById('authSwitch');
        const signupFields = document.getElementById('signupFields');
        const confirmPassGroup = document.getElementById('confirmPassGroup');
        const rememberMeRow = document.getElementById('rememberMeRow');
        const authHeading = document.getElementById('authHeading');
        const authSubheading = document.getElementById('authSubheading');
        const authBtn = document.getElementById('authBtn');

        authSwitch.addEventListener('click', () => {
            isSignupMode = !isSignupMode;
            if (isSignupMode) {
                authHeading.textContent = 'Registration';
                authSubheading.textContent = 'Create a new account with your info';
                signupFields.style.display = 'block';
                confirmPassGroup.style.display = 'block';
                rememberMeRow.style.display = 'none';
                authBtn.textContent = 'Register';
                authSwitch.innerHTML = 'Already have an account? <span>Login</span>';
            } else {
                authHeading.textContent = 'Login';
                authSubheading.textContent = 'Sign in to your account';
                signupFields.style.display = 'none';
                confirmPassGroup.style.display = 'none';
                rememberMeRow.style.display = 'flex';
                authBtn.textContent = 'Login';
                authSwitch.innerHTML = 'Need an account? <span>Register</span>';
            }
        });

        authBtn.addEventListener('click', async () => {
            const email = document.getElementById('authEmail').value.trim().toLowerCase();
            const pass = document.getElementById('authPassword').value.trim();

            if (!email || !pass) return alert('Email and password are required');
            if (pass.length < 6) return alert('Password must be at least 6 characters');

            try {
                if (isSignupMode) {
                    const name = document.getElementById('regName').value.trim();
                    const confirmPass = document.getElementById('authConfirmPassword').value.trim();
                    const country = document.getElementById('regCountry').value;

                    if (!name) return alert('Please provide Your Name');
                    if (pass !== confirmPass) return alert('Passwords do not match!');

                    const check = await db.collection('users').where('email', '==', email).get();
                    if (!check.empty) return alert('An account with this email already exists!');

                    const newUid = Math.floor(10000000 + Math.random() * 90000000).toString();
                    const pubKeyJwk = await initOrLoadKeys(newUid);

                    // E2EE: Encrypt Private Key with PBKDF2
                    const privJwkStr = localStorage.getItem('ghost_priv_key_' + newUid);
                    let encryptedPriv = null;
                    let privIv = null;
                    if (privJwkStr) {
                        try {
                            const encResult = await encryptPrivateKey(privJwkStr, pass, newUid);
                            encryptedPriv = encResult.encryptedData;
                            privIv = encResult.iv;
                        } catch(e) { console.error("Private key encryption failed:", e); }
                    }

                    await db.collection('users').doc(newUid).set({
                        uid: newUid,
                        name: name,
                        email: email,
                        password: pass,
                        gender: selectedGender,
                        country: country,
                        bio: "Welcome to GhostChat! I'm new here.",
                        publicKey: pubKeyJwk,
                        encryptedPrivateKey: encryptedPriv || null,
                        iv: privIv || null,
                        friends: [],
                        incomingRequests: [],
                        sentRequests: [],
                        createdAt: firebase.firestore.FieldValue.serverTimestamp()
                    });

                    // âœ… FIX: Save basic info to the aggregated document for cheap reads
                    try {
                        await db.collection('AggregatedData').doc('all_users').set({
                            list: firebase.firestore.FieldValue.arrayUnion({
                                uid: newUid,
                                name: name,
                                gender: selectedGender,
                                country: country
                            })
                        }, { merge: true });
                    } catch(err) {
                        console.error('Failed to update aggregated users list', err);
                    }

                    localStorage.setItem('ghost_chat_uid', newUid);
                    loginSuccess(newUid);
                } else {
                    const q = await db.collection('users')
                        .where('email', '==', email)
                        .where('password', '==', pass)
                        .get();

                    if (q.empty) return alert('Incorrect Email or Password!');

                    const userDoc = q.docs[0];
                    const uid = userDoc.id;
                    const userData = userDoc.data();

                    // E2EE: Decrypt Private Key on new device
                    if (userData.encryptedPrivateKey && userData.iv) {
                        try {
                            const decryptedJwkString = await decryptPrivateKey(userData.encryptedPrivateKey, userData.iv, pass, uid);
                            localStorage.setItem('ghost_priv_key_' + uid, decryptedJwkString);
                            if (userData.publicKey) {
                                localStorage.setItem('ghost_pub_key_' + uid, JSON.stringify(userData.publicKey));
                            }
                        } catch (err) {
                            console.error("Failed to decrypt private key. Wrong password?", err);
                        }
                    }

                    const remember = document.getElementById('rememberMeCheck').checked;
                    if (remember) localStorage.setItem('ghost_chat_uid', uid);
                    else sessionStorage.setItem('ghost_chat_uid', uid);

                    loginSuccess(uid);
                }
            } catch (err) { alert(err.message); }
        });

        window.addEventListener('DOMContentLoaded', () => {
            const savedUid = localStorage.getItem('ghost_chat_uid') || sessionStorage.getItem('ghost_chat_uid');
            if (savedUid) loginSuccess(savedUid);
            syncOnlineTime().then(startLiveClock);
            
            // Load saved language
            const savedLang = localStorage.getItem('ghostchat_lang') || 'en';
            const langSelect = document.getElementById('languageSelect');
            if (langSelect) langSelect.value = savedLang;
            if (typeof changeLanguage === 'function') changeLanguage(savedLang);
        });

        let timeOffsetMs = 0;

        async function syncOnlineTime() {
            try {
                const response = await fetch('https://worldtimeapi.org/api/timezone/Asia/Dhaka');
                const data = await response.json();
                const onlineTime = new Date(data.datetime).getTime();
                const localTime = Date.now();
                timeOffsetMs = onlineTime - localTime;
            } catch (err) {
                console.error("Time sync failed:", err);
            }
        }

        function startLiveClock() {
            setInterval(() => {
                const now = new Date(Date.now() + timeOffsetMs);
                const options = { timeZone: 'Asia/Dhaka', hour: '2-digit', minute: '2-digit', hour12: true };
                const timeStr = now.toLocaleTimeString('en-US', options);
                const clockEl = document.getElementById('liveClockTime');
                if (clockEl) clockEl.textContent = timeStr;
            }, 1000);
        }

        async function loginSuccess(uid) {
            currentUserId = uid;
            if (unsubscribeProfile) unsubscribeProfile();
            if (unsubscribeGroups) unsubscribeGroups();

            const pubKeyJwk = await initOrLoadKeys(uid);

            unsubscribeProfile = db.collection('users').doc(uid).onSnapshot(async doc => {
                if (doc.exists) {
                    myProfile = doc.data();
                    // âœ… FIX: à¦¶à§à¦§à§à¦®à¦¾à¦¤à§à¦° publicKey à¦¸à¦®à§à¦ªà§‚à¦°à§à¦£ absent à¦¹à¦²à§‡à¦‡ write à¦•à¦°à§‹à¥¤
                    // JSON.stringify comparison à¦•à¦–à¦¨à§‹ à¦•à¦–à¦¨à§‹ property order-à¦à¦° à¦•à¦¾à¦°à¦£à§‡
                    // false à¦¦à§‡à¦¯à¦¼ à¦à¦¬à¦‚ à¦…à¦¨à¦¨à§à¦¤ writeâ†’snapshotâ†’write loop à¦¤à§ˆà¦°à¦¿ à¦•à¦°à§‡à¥¤
                    if (!myProfile.publicKey) {
                        await db.collection('users').doc(uid).update({ publicKey: pubKeyJwk });
                    }
                    updateProfileUI();
                    renderFriendsSubTab();
                    renderChatsTab();
                } else {
                    logout();
                }
            });

            unsubscribeGroups = db.collection('groups').where('members', 'array-contains', uid).onSnapshot(snapshot => {
                myGroups = [];
                snapshot.forEach(doc => {
                    myGroups.push(doc.data());
                    if (client && client.connected) {
                        client.subscribe('ghostchat/group/' + doc.id);
                    }
                });
                renderChatsTab();
            });

            setupMQTT();
            await syncOfflineMailbox();
            loadAllUsers();
            showScreen('dashScreen');
        }

        function logout() {
            if (unsubscribeProfile) unsubscribeProfile();
            if (unsubscribeGroups) unsubscribeGroups();
            if (client) {
                // à¦¤à¦¾à§Žà¦•à§à¦·à¦£à¦¿à¦• Offline à¦¸à§à¦Ÿà§à¦¯à¦¾à¦Ÿà¦¾à¦¸ à¦ªà¦¾à¦¬à¦²à¦¿à¦¶
                client.publish('ghostchat/status/' + currentUserId, 'offline', { qos: 1, retain: true }, () => {
                    client.end();
                });
            }
            localStorage.removeItem('ghost_chat_uid');
            sessionStorage.removeItem('ghost_chat_uid');
            currentUserId = null;
            myProfile = null;
            myPrivKeyObj = null;
            aesKeyCache.clear();
            userStatusMap.clear();
            // âœ… FIX: Logout-à¦ cache à¦ªà¦°à¦¿à¦·à§à¦•à¦¾à¦° à¦•à¦°à§‹ â€” à¦¨à¦¤à§à¦¨ session-à¦ fresh data à¦ªà¦¾à¦¬à§‡
            allUsersCache = null;
            allUsersCacheTime = 0;
            liveChannelsCache = null;
            if (unsubscribeProfile) unsubscribeProfile();
            showScreen('authScreen');
        }

        document.getElementById('logoutBtn').addEventListener('click', logout);

        function updateProfileUI() {
            document.getElementById('myDisplayName').textContent = 'ME';
            document.getElementById('myCountryFlag').textContent = flags[myProfile.country] || 'ðŸŒ';
            document.getElementById('myGenderIcon').textContent = myProfile.gender === 'female' ? '👩' : '👨';
            document.getElementById('myAvatar').innerHTML = renderAvatar(myProfile.avatarUrl, myProfile.gender);
        }

        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btn.classList.add('active');
            if (tabId === 'tabAll') loadAllUsers();
            if (tabId === 'tabFriends') updateUnreadBadges();
            if (tabId === 'tabChats') renderChatsTab();
            if (tabId === 'tabLive') loadLiveChannels();
        }

        function renderChatsTab() {
            const chatsListEl = document.getElementById('chatsList');
            if (!chatsListEl) return;
            chatsListEl.innerHTML = '';

            if ((!myProfile || !myProfile.friends || myProfile.friends.length === 0) && myGroups.length === 0) {
                chatsListEl.innerHTML = '<div class="empty-placeholder">No conversations yet</div>';
                return;
            }

            let chatData = [];

            if (myProfile && myProfile.friends) {
                myProfile.friends.forEach(f => {
                    const list = getLocalChat(f.uid);
                    if (list.length > 0) {
                        const lastMsg = list[list.length - 1];
                        const unreadCount = getUnreadCount(f.uid);
                        chatData.push({
                            type: 'friend',
                            target: f,
                            lastMsg: lastMsg,
                            unreadCount: unreadCount,
                            timestamp: lastMsg.timestamp
                        });
                    } else {
                        chatData.push({
                            type: 'friend',
                            target: f,
                            lastMsg: { text: 'Say hi!', sender: '' },
                            unreadCount: 0,
                            timestamp: f.addedAt || Date.now()
                        });
                    }
                });
            }

            myGroups.forEach(g => {
                const list = getLocalGroupChat(g.id);
                if (list.length > 0) {
                    const lastMsg = list[list.length - 1];
                    const unreadCount = getGroupUnreadCount(g.id);
                    chatData.push({
                        type: 'group',
                        target: g,
                        lastMsg: lastMsg,
                        unreadCount: unreadCount,
                        timestamp: lastMsg.timestamp
                    });
                } else {
                    chatData.push({
                        type: 'group',
                        target: g,
                        lastMsg: { text: 'Group created', sender: '' },
                        unreadCount: 0,
                        timestamp: g.createdAt || Date.now()
                    });
                }
            });

            chatData.sort((a, b) => b.timestamp - a.timestamp);

            if (chatData.length === 0) {
                chatsListEl.innerHTML = '<div class="empty-placeholder">No conversations yet</div>';
                return;
            }

            chatData.forEach(data => {
                const isUnread = data.unreadCount > 0;
                const div = document.createElement('div');
                div.className = 'user-card';
                div.style.cursor = 'pointer';
                if (isUnread) {
                    div.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
                    div.style.borderColor = 'rgba(239, 68, 68, 0.4)';
                }

                if (data.type === 'friend') {
                    const f = data.target;
                    const status = userStatusMap.get(f.uid) || 'offline';
                    div.onclick = () => openPrivateChat(f.uid, f.name, f.gender);
                    div.innerHTML = `
                    <div class="user-card-info" style="flex: 1; min-width: 0;">
                        <div class="card-avatar" onclick="event.stopPropagation(); openUserProfile('${f.uid}')" title="View Profile" style="z-index: 2;">
                            ${renderAvatar(f.avatarUrl, f.gender)}
                            <div class="status-dot ${status}" id="chat_status_dot_${f.uid}"></div>
                        </div>
                        <div style="flex: 1; min-width: 0; display: flex; flex-direction: column; justify-content: center;">
                            <div class="card-name" style="${isUnread ? 'font-weight: 800; color: var(--danger);' : ''}">${f.name}</div>
                            <div style="font-size: 0.8rem; margin-top: 3px; color: ${isUnread ? 'var(--text-main)' : 'var(--text-muted)'}; font-weight: ${isUnread ? '600' : '400'}; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                                ${data.lastMsg.sender === currentUserId ? 'You: ' : ''}${data.lastMsg.text}
                            </div>
                        </div>
                    </div>
                `;
                } else {
                    const g = data.target;
                    div.onclick = () => openGroupChat(g);
                    div.innerHTML = `
                    <div class="user-card-info" style="flex: 1; min-width: 0;">
                        <div class="card-avatar" style="background: linear-gradient(135deg, #10b981, #3b82f6);">
                            ðŸ‘¥
                        </div>
                        <div style="flex: 1; min-width: 0; display: flex; flex-direction: column; justify-content: center;">
                            <div class="card-name" style="${isUnread ? 'font-weight: 800; color: var(--danger);' : ''}">${g.name}</div>
                            <div style="font-size: 0.8rem; margin-top: 3px; color: ${isUnread ? 'var(--text-main)' : 'var(--text-muted)'}; font-weight: ${isUnread ? '600' : '400'}; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                                ${data.lastMsg.sender === currentUserId ? 'You: ' : (data.lastMsg.senderName ? data.lastMsg.senderName + ': ' : '')}${data.lastMsg.text}
                            </div>
                        </div>
                    </div>
                `;
                }

                div.innerHTML += `
                <div style="font-size: 0.7rem; color: var(--text-muted); text-align: right; min-width: 60px; display: flex; flex-direction: column; align-items: flex-end; gap: 4px;">
                    <div>${new Date(data.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
                    ${isUnread ? `<div style="background: var(--danger); color: white; border-radius: 50%; width: 20px; height: 20px; text-align: center; line-height: 20px; font-weight: bold; font-size: 0.75rem;">${data.unreadCount}</div>` : ''}
                </div>
            `;
                chatsListEl.appendChild(div);
            });
        }

        function switchFriendsSubTab(sub) {
            document.getElementById('pillFriendsBtn').className = 'sub-pill-btn ' + (sub === 'friends' ? 'active' : '');
            document.getElementById('pillRequestsBtn').className = 'sub-pill-btn ' + (sub === 'requests' ? 'active' : '');
            document.getElementById('subFriendsSection').style.display = sub === 'friends' ? 'block' : 'none';
            document.getElementById('subRequestsList').style.display = sub === 'requests' ? 'block' : 'none';
            if(document.getElementById('pillSearchBtn')) document.getElementById('pillSearchBtn').className = 'sub-pill-btn ' + (sub === 'search' ? 'active' : '');
            if(document.getElementById('subSearchList')) document.getElementById('subSearchList').style.display = sub === 'search' ? 'block' : 'none';
        }

        // --- à¦ªà§à¦°à§‡à¦œà§‡à¦¨à§à¦¸ à¦†à¦ªà¦¡à§‡à¦Ÿ UI à¦¹à§‡à¦²à§à¦ªà¦¾à¦° ---
        function updatePresenceUI(targetUid, status) {
            userStatusMap.set(targetUid, status);

            // à§§. à¦«à§à¦°à§‡à¦¨à§à¦¡à¦²à¦¿à¦¸à§à¦Ÿ à¦¡à¦Ÿ à¦†à¦ªà¦¡à§‡à¦Ÿ
            const friendDot = document.getElementById(`status_dot_${targetUid}`);
            if (friendDot) {
                friendDot.className = `status-dot ${status}`;
            }

            // à§¨. à¦…à¦² à¦‡à¦‰à¦œà¦¾à¦° à¦¡à¦Ÿ à¦†à¦ªà¦¡à§‡à¦Ÿ
            const allDot = document.getElementById(`all_status_dot_${targetUid}`);
            if (allDot) {
                allDot.className = `status-dot ${status}`;
            }

            // à§©. à¦šà§à¦¯à¦¾à¦Ÿ à¦¹à§‡à¦¡à¦¾à¦° à¦†à¦ªà¦¡à§‡à¦Ÿ (à¦¯à¦¦à¦¿ à¦šà§à¦¯à¦¾à¦Ÿ à¦“à¦ªà§‡à¦¨ à¦¥à¦¾à¦•à§‡)
            if (activeFriendUid === targetUid) {
                updateChatHeaderPresence(status);
            }
        }

        function updateChatHeaderPresence(status) {
            const headerDot = document.getElementById('chatHeaderDot');
            const headerText = document.getElementById('chatPartnerStatusText');
            if (headerDot) headerDot.className = `status-dot ${status}`;
            if (headerText) {
                headerText.textContent = status === 'online'
                    ? '🟢 Online â€¢ 🔒 E2EE 48h'
                    : '⚪ Offline â€¢ 🔒 E2EE 48h';
                headerText.style.color = status === 'online' ? '#10b981' : 'var(--text-muted)';
            }
        }

        async function loadAllUsers() {
            const container = document.getElementById('allUsersList');
            try {
                // âœ… FIX: Cache â€” à§« à¦®à¦¿à¦¨à¦¿à¦Ÿà§‡à¦° à¦®à¦§à§à¦¯à§‡ à¦†à¦¬à¦¾à¦° call à¦¹à¦²à§‡ Firebase hit à¦•à¦°à¦¬à§‡ à¦¨à¦¾
                const now = Date.now();
                let usersList = [];
                if (allUsersCache && (now - allUsersCacheTime) < ALL_USERS_CACHE_TTL) {
                    usersList = allUsersCache;
                } else {
                    // Fetch from the aggregated single document (1 Read)
                    const snap = await db.collection('AggregatedData').doc('all_users').get();
                    if (snap.exists && snap.data().list) {
                        usersList = snap.data().list;
                    }
                    allUsersCache = usersList;
                    allUsersCacheTime = now;
                }
                
                container.innerHTML = '';
                if (!usersList || usersList.length === 0) return;

                // Randomize (Shuffle) array to show random users
                let shuffled = [...usersList].sort(() => 0.5 - Math.random());
                
                // Show up to 50 random users
                let count = 0;
                for (const u of shuffled) {
                    if (count >= 50) break;
                    if (u.uid === currentUserId) continue;

                    const isFriend = myProfile.friends && myProfile.friends.some(f => f.uid === u.uid);
                    const isRequested = myProfile.sentRequests && myProfile.sentRequests.includes(u.uid);
                    const status = userStatusMap.get(u.uid) || 'offline';

                    let btnHtml = '';
                    if (isFriend) {
                        btnHtml = `<button class="btn-card btn-chat" onclick="openPrivateChat('${u.uid}', '${u.name}', '${u.gender}')">Chat</button>`;
                    } else if (isRequested) {
                        btnHtml = `<button class="btn-card btn-add" disabled>Requested</button>`;
                    } else {
                        btnHtml = `<button class="btn-card btn-add" onclick="sendFriendRequest('${u.uid}')">Add Friend</button>`;
                    }

                    const card = document.createElement('div');
                    card.className = 'user-card';
                    card.innerHTML = `
                    <div class="user-card-info" style="cursor: pointer;" onclick="openUserProfile('${u.uid}')">
                        <div class="card-avatar">
                            ${renderAvatar(u.avatarUrl, u.gender)}
                            <div class="status-dot ${status}" id="all_status_dot_${u.uid}"></div>
                        </div>
                        <div>
                            <div class="card-name">${u.name} ${flags[u.country] || ''}</div>
                            <div class="card-meta">UID: ${u.uid.substring(0, 7)}...</div>
                        </div>
                    </div>
                    <div>${btnHtml}</div>
                `;
                    container.appendChild(card);
                    count++;
                }
            } catch (e) { console.error(e); }
        }

        async function sendFriendRequest(targetUid) {
            try {
                await db.collection('users').doc(targetUid).update({
                    incomingRequests: firebase.firestore.FieldValue.arrayUnion({
                        uid: currentUserId,
                        name: myProfile.name,
                        gender: myProfile.gender,
                        country: myProfile.country
                    })
                });
                await db.collection('users').doc(currentUserId).update({
                    sentRequests: firebase.firestore.FieldValue.arrayUnion(targetUid)
                });
                alert('Friend Request Sent!');
                loadAllUsers();
            } catch (e) { alert(e.message); }
        }

        window.openCreateGroupScreen = () => {
            const listEl = document.getElementById('groupMembersSelectionList');
            listEl.innerHTML = '';
            if (!myProfile.friends || myProfile.friends.length === 0) {
                listEl.innerHTML = '<div style="color: var(--text-muted); font-size: 0.9rem;">You have no friends to add.</div>';
            } else {
                myProfile.friends.forEach(f => {
                    const item = document.createElement('label');
                    item.style.display = 'flex';
                    item.style.alignItems = 'center';
                    item.style.gap = '10px';
                    item.style.marginBottom = '10px';
                    item.style.cursor = 'pointer';
                    item.innerHTML = `
                    <input type="checkbox" class="group-member-cb" value="${f.uid}" style="width: 18px; height: 18px;">
                    <div style="flex: 1; color: var(--text-main); font-size: 1rem;">${f.name} ${flags[f.country] || ''}</div>
                `;
                    listEl.appendChild(item);
                });
            }
            document.getElementById('newGroupName').value = '';
            showScreen('createGroupScreen');
        };

        window.createGroup = async () => {
            const name = document.getElementById('newGroupName').value.trim();
            if (!name) return alert('Enter group name');

            const cbs = document.querySelectorAll('.group-member-cb:checked');
            const memberUids = Array.from(cbs).map(cb => cb.value);
            if (memberUids.length === 0) return alert('Select at least one friend');

            memberUids.push(currentUserId);

            const btn = document.getElementById('createGroupConfirmBtn');
            btn.textContent = 'Creating...';
            btn.disabled = true;

            try {
                const groupId = 'grp_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6);
                const groupData = {
                    id: groupId,
                    name: name,
                    creator: currentUserId,
                    members: memberUids,
                    createdAt: Date.now()
                };

                await db.collection('groups').doc(groupId).set(groupData);

                if (client && client.connected) {
                    client.subscribe('ghostchat/group/' + groupId);
                }

                alert('Group Created Successfully!');
                showScreen('dashScreen');
                renderChatsTab();
            } catch (e) {
                alert('Error: ' + e.message);
            } finally {
                btn.textContent = 'Create Group';
                btn.disabled = false;
            }
        };

        function renderFriendsSubTab() {
            const friendsCont = document.getElementById('subFriendsList');
            const reqCont = document.getElementById('subRequestsList');
            const reqCount = document.getElementById('reqCount');

            const reqs = myProfile.incomingRequests || [];
            reqCount.textContent = reqs.length;

            friendsCont.innerHTML = '';
            if (!myProfile.friends || myProfile.friends.length === 0) {
                friendsCont.innerHTML = '<div class="empty-placeholder">Your friend list is empty</div>';
            } else {
                myProfile.friends.forEach(f => {
                    const unread = getUnreadCount(f.uid);
                    const status = userStatusMap.get(f.uid) || 'offline';
                    const item = document.createElement('div');
                    item.className = 'user-card';
                    item.innerHTML = `
                    <div class="user-card-info" style="cursor: pointer;" onclick="openUserProfile('${f.uid}')">
                        <div class="card-avatar">
                            ${renderAvatar(f.avatarUrl, f.gender)}
                            <div class="status-dot ${status}" id="status_dot_${f.uid}"></div>
                        </div>
                        <div>
                            <div class="card-name">
                                <span>${f.name} ${flags[f.country] || ''}</span>
                                <span class="unread-badge" id="unread_badge_${f.uid}" style="${unread > 0 ? '' : 'display:none;'}">🔴 ${unread}</span>
                            </div>
                            <div class="card-meta">Friend</div>
                        </div>
                    </div>
                    <button class="btn-card btn-chat" onclick="openPrivateChat('${f.uid}', '${f.name}', '${f.gender}')">Chat</button>
                `;
                    friendsCont.appendChild(item);
                });
            }

            reqCont.innerHTML = '';
            if (reqs.length === 0) {
                reqCont.innerHTML = '<div class="empty-placeholder">No pending friend requests</div>';
            } else {
                reqs.forEach(r => {
                    const item = document.createElement('div');
                    item.className = 'user-card';
                    item.innerHTML = `
                    <div class="user-card-info" style="cursor: pointer;" onclick="openUserProfile('${r.uid}')">
                        <div class="card-avatar">${renderAvatar(r.avatarUrl, r.gender)}</div>
                        <div>
                            <div class="card-name">${r.name} ${flags[r.country] || ''}</div>
                            <div class="card-meta">Wants to be friends</div>
                        </div>
                    </div>
                    <div>
                        <button class="btn-card btn-accept" onclick="acceptRequest('${r.uid}')">Accept</button>
                        <button class="btn-card btn-reject" onclick="rejectRequest('${r.uid}')">Reject</button>
                    </div>
                `;
                    reqCont.appendChild(item);
                });
            }
        }

        async function acceptRequest(senderUid) {
            try {
                const senderDoc = await db.collection('users').doc(senderUid).get();
                const senderData = senderDoc.data();

                const now = Date.now();
                await db.collection('users').doc(currentUserId).update({
                    friends: firebase.firestore.FieldValue.arrayUnion({
                        uid: senderData.uid,
                        name: senderData.name,
                        gender: senderData.gender,
                        country: senderData.country,
                        addedAt: now
                    }),
                    incomingRequests: myProfile.incomingRequests.filter(r => r.uid !== senderUid)
                });

                await db.collection('users').doc(senderUid).update({
                    friends: firebase.firestore.FieldValue.arrayUnion({
                        uid: currentUserId,
                        name: myProfile.name,
                        gender: myProfile.gender,
                        country: myProfile.country,
                        addedAt: now
                    }),
                    sentRequests: firebase.firestore.FieldValue.arrayRemove(currentUserId)
                });

                alert('Friend Added!');
            } catch (e) { alert(e.message); }
        }

        async function rejectRequest(senderUid) {
            try {
                await db.collection('users').doc(currentUserId).update({
                    incomingRequests: myProfile.incomingRequests.filter(r => r.uid !== senderUid)
                });
                await db.collection('users').doc(senderUid).update({
                    sentRequests: firebase.firestore.FieldValue.arrayRemove(currentUserId)
                });
            } catch (e) { alert(e.message); }
        }

        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    document.getElementById('searchBtn').click();
                }
            });
        }

        document.getElementById('searchBtn').addEventListener('click', async () => {
            const term = document.getElementById('searchInput').value.trim();
            const results = document.getElementById('searchResults');
            if (!term) return;

            results.innerHTML = '<div class="empty-placeholder">Searching...</div>';
            try {
                let doc = await db.collection('users').doc(term).get();
                let usersFound = [];

                if (doc.exists && doc.id !== currentUserId) {
                    usersFound.push(doc.data());
                } else {
                    const q = await db.collection('users').where('name', '==', term).get();
                    q.forEach(d => {
                        if (d.id !== currentUserId) usersFound.push(d.data());
                    });
                }

                results.innerHTML = '';
                if (usersFound.length === 0) {
                    results.innerHTML = '<div class="empty-placeholder">No user found</div>';
                    return;
                }

                usersFound.forEach(u => {
                    const isFriend = myProfile.friends && myProfile.friends.some(f => f.uid === u.uid);
                    const isRequested = myProfile.sentRequests && myProfile.sentRequests.includes(u.uid);
                    const status = userStatusMap.get(u.uid) || 'offline';

                    let btnHtml = isFriend
                        ? `<button class="btn-card btn-chat" onclick="openPrivateChat('${u.uid}', '${u.name}', '${u.gender}')">Chat</button>`
                        : (isRequested ? `<button class="btn-card btn-add" disabled>Requested</button>` : `<button class="btn-card btn-add" onclick="sendFriendRequest('${u.uid}')">Add Friend</button>`);

                    const card = document.createElement('div');
                    card.className = 'user-card';
                    card.innerHTML = `
                    <div class="user-card-info" style="cursor: pointer;" onclick="openUserProfile('${u.uid}')">
                        <div class="card-avatar">
                            ${renderAvatar(u.avatarUrl, u.gender)}
                            <div class="status-dot ${status}"></div>
                        </div>
                        <div>
                            <div class="card-name">${u.name} ${flags[u.country] || ''}</div>
                            <div class="card-meta">UID: ${u.uid}</div>
                        </div>
                    </div>
                    <div>${btnHtml}</div>
                `;
                    results.appendChild(card);
                });
            } catch (e) { console.error(e); }
        });

        // --- MQTT à¦²à¦¾à¦‡à¦­ à¦‡à¦žà§à¦œà¦¿à¦¨ à¦“ LWT à¦ªà§à¦°à§‡à¦œà§‡à¦¨à§à¦¸ à¦†à¦°à§à¦•à¦¿à¦Ÿà§‡à¦•à¦šà¦¾à¦° ---
        function setupMQTT() {
            const myTopic = 'ghostchat/user/' + currentUserId;
            const myStatusTopic = 'ghostchat/status/' + currentUserId;

            // LWT (Last Will and Testament): à¦¸à¦‚à¦¯à§‹à¦— à¦¬à¦¿à¦šà§à¦›à¦¿à¦¨à§à¦¨ à¦¹à¦“à§Ÿà¦¾ à¦®à¦¾à¦¤à§à¦° à¦¬à§à¦°à§‹à¦•à¦¾à¦° à¦¨à¦¿à¦œà§‡ à¦¥à§‡à¦•à§‡à¦‡ 'offline' à¦ªà¦¾à¦ à¦¾à¦¬à§‡
            client = mqtt.connect('wss://broker.emqx.io:8084/mqtt', {
                clientId: 'client_' + currentUserId + '_' + Math.random().toString(36).substring(2, 6),
                clean: true,
                reconnectPeriod: 2000,
                will: {
                    topic: myStatusTopic,
                    payload: 'offline',
                    qos: 1,
                    retain: true
                }
            });

            client.on('connect', () => {
                client.subscribe(myTopic);
                client.subscribe('ghostchat/status/+'); // à¦¸à¦¬ à¦«à§à¦°à§‡à¦¨à§à¦¡à§‡à¦° à¦¸à§à¦Ÿà§à¦¯à¦¾à¦Ÿà¦¾à¦¸ à¦Ÿà§à¦°à§à¦¯à¦¾à¦•
                myGroups.forEach(g => client.subscribe('ghostchat/group/' + g.id));

                // Onlineà§‡ à¦ªà§à¦°à¦¬à§‡à¦¶ à¦•à¦°à¦¾à¦° à¦¸à¦¾à¦¥à§‡ à¦¸à¦¾à¦¥à§‡ retain: true à¦¸à¦¹ 'online' à¦¸à¦¿à¦—à¦¨à§à¦¯à¦¾à¦² à¦ªà§à¦°à¦šà¦¾à¦°
                client.publish(myStatusTopic, 'online', { qos: 1, retain: true });
            });

            client.on('message', async (topic, message) => {
                try {
                    // à§§. Online / Offline à¦ªà§à¦°à§‡à¦œà§‡à¦¨à§à¦¸ à¦¹à§à¦¯à¦¾à¦¨à§à¦¡à¦²à¦¾à¦°
                    if (topic.startsWith('ghostchat/status/')) {
                        const senderUid = topic.replace('ghostchat/status/', '');
                        const status = message.toString().trim(); // 'online' à¦…à¦¥à¦¬à¦¾ 'offline'
                        updatePresenceUI(senderUid, status);
                        return;
                    }

                    // à§¨. à¦®à§‡à¦¸à§‡à¦œ à¦“ ACK à¦¹à§à¦¯à¦¾à¦¨à§à¦¡à¦²à¦¿à¦‚
                    const data = JSON.parse(message.toString());

                    // ACK à¦ªà§à¦°à¦¾à¦ªà§à¦¤à¦¿ (à¦®à§‡à¦¸à§‡à¦œ à¦…à¦ªà¦° à¦ªà§à¦°à¦¾à¦¨à§à¦¤à§‡ à¦ªà§Œà¦à¦›à¦¾à¦¨à§‹à¦° à¦•à¦¨à¦«à¦¾à¦°à§à¦®à§‡à¦¶à¦¨)
                    if (data.type === 'msg_ack' && data.toUid === currentUserId) {
                        if (pendingAckTimers.has(data.msgId)) {
                            clearTimeout(pendingAckTimers.get(data.msgId));
                            pendingAckTimers.delete(data.msgId);
                        }
                        updateLocalMessageStatus(data.fromUid, data.msgId, 'delivered');
                        return;
                    }

                    // SEEN à¦ªà§à¦°à¦¾à¦ªà§à¦¤à¦¿ (à¦®à§‡à¦¸à§‡à¦œ à¦…à¦ªà¦° à¦ªà§à¦°à¦¾à¦¨à§à¦¤à§‡ à¦¦à§‡à¦–à¦¾ à¦¹à§Ÿà§‡à¦›à§‡)
                    if (data.type === 'msg_seen' && data.toUid === currentUserId) {
                        updateLocalMessagesAsRead(data.fromUid);
                        return;
                    }

                    // à§©. à¦—à§à¦°à§à¦ª à¦®à§‡à¦¸à§‡à¦œ à¦—à§à¦°à¦¹à¦£
                    if (data.type === 'group_chat' && topic.startsWith('ghostchat/group/')) {
                        if (data.sender === currentUserId) return;

                        const myEncryptedPayload = data.payloads && data.payloads[currentUserId];
                        if (!myEncryptedPayload) return;

                        let aesKey = aesKeyCache.get(data.sender);
                        if (!aesKey) {
                            const senderDoc = await db.collection('users').doc(data.sender).get();
                            if (senderDoc.exists && senderDoc.data().publicKey) {
                                aesKey = await computeAESKeyWith(senderDoc.data().publicKey);
                                aesKeyCache.set(data.sender, aesKey);
                            }
                        }

                        if (aesKey) {
                            try {
                                const plainText = await decryptPayload(myEncryptedPayload, aesKey);
                                const isChatOpen = (activeGroupId === data.groupId);

                                saveGroupMessageLocally(data.groupId, {
                                    id: data.id,
                                    sender: data.sender,
                                    text: plainText,
                                    timestamp: data.timestamp || Date.now(),
                                    status: 'delivered',
                                    unread: !isChatOpen,
                                    senderName: data.senderName
                                });

                                if (isChatOpen) {
                                    appendMessageBubble({
                                        id: data.id,
                                        text: plainText,
                                        sender: 'stranger',
                                        timestamp: data.timestamp,
                                        status: 'delivered',
                                        senderName: data.senderName
                                    });
                                } else {
                                    updateUnreadBadges();
                                    const groupName = myGroups.find(g => g.id === data.groupId)?.name || 'Group';
                                    const banner = document.getElementById('notifyBanner');
                                    document.getElementById('notifySender').textContent = groupName;
                                    document.getElementById('notifyText').textContent = `${data.senderName}: sent a message`;
                                    banner.style.display = 'flex';
                                    document.getElementById('notifyOpenBtn').onclick = () => {
                                        banner.style.display = 'none';
                                        const g = myGroups.find(gr => gr.id === data.groupId);
                                        if (g) openGroupChat(g);
                                    };
                                    setTimeout(() => { banner.style.display = 'none'; }, 6000);
                                }
                                renderChatsTab();
                            } catch (err) { }
                        }
                        return;
                    }

                    // à¦²à¦¾à¦‡à¦­ à¦®à§‡à¦¸à§‡à¦œ à¦—à§à¦°à¦¹à¦£
                    if (data.type === 'live_chat' && data.targetUid === currentUserId) {
                        // à¦¤à¦¾à§Žà¦•à§à¦·à¦£à¦¿à¦• ACK à¦°à¦¿à¦Ÿà¦¾à¦°à§à¦¨ (à¦ªà§à¦°à§‡à¦°à¦•à§‡à¦° à¦Ÿà¦¾à¦‡à¦®à¦¾à¦° à¦¬à¦¨à§à¦§ à¦•à¦°à¦¾)
                        client.publish('ghostchat/user/' + data.sender, JSON.stringify({
                            type: 'msg_ack',
                            msgId: data.id,
                            fromUid: currentUserId,
                            toUid: data.sender
                        }));

                        let aesKey = aesKeyCache.get(data.sender);
                        if (!aesKey) {
                            const senderDoc = await db.collection('users').doc(data.sender).get();
                            if (senderDoc.exists && senderDoc.data().publicKey) {
                                aesKey = await computeAESKeyWith(senderDoc.data().publicKey);
                                aesKeyCache.set(data.sender, aesKey);
                            }
                        }

                        if (aesKey) {
                            try {
                                const plainText = await decryptPayload(data.payload, aesKey);
                                const isChatOpen = (activeFriendUid === data.sender);

                                saveMessageLocally(data.sender, {
                                    id: data.id,
                                    sender: data.sender,
                                    text: plainText,
                                    timestamp: data.timestamp || Date.now(),
                                    status: 'delivered',
                                    unread: !isChatOpen
                                });

                                if (isChatOpen) {
                                    appendMessageBubble({
                                        id: data.id,
                                        text: plainText,
                                        sender: 'stranger',
                                        timestamp: data.timestamp,
                                        status: 'delivered'
                                    });
                                    client.publish('ghostchat/user/' + data.sender, JSON.stringify({
                                        type: 'msg_seen',
                                        fromUid: currentUserId,
                                        toUid: data.sender
                                    }));
                                } else {
                                    updateUnreadBadges();
                                    const banner = document.getElementById('notifyBanner');
                                    document.getElementById('notifySender').textContent = data.senderName;
                                    document.getElementById('notifyText').textContent = 'sent you a message';
                                    banner.style.display = 'flex';
                                    document.getElementById('notifyOpenBtn').onclick = () => {
                                        banner.style.display = 'none';
                                        openPrivateChat(data.sender, data.senderName, 'male');
                                    };
                                    setTimeout(() => { banner.style.display = 'none'; }, 6000);
                                }
                            } catch (decryptErr) {
                                console.error("à¦¡à¦¿à¦•à§à¦°à¦¿à¦ªà¦¶à¦¨ à¦¤à§à¦°à§à¦Ÿà¦¿:", decryptErr);
                                aesKeyCache.delete(data.sender);
                            }
                        }
                    }
                } catch (err) { console.error("MQTT à¦‡à¦­à§‡à¦¨à§à¦Ÿ à¦¤à§à¦°à§à¦Ÿà¦¿:", err); }
            });
        }

        function updateLocalMessageStatus(friendUid, msgId, newStatus) {
            const key = `ghost_msgs_${currentUserId}_${friendUid}`;
            const list = getLocalChat(friendUid);
            const msg = list.find(m => m.id === msgId);
            if (msg) {
                msg.status = newStatus;
                localStorage.setItem(key, JSON.stringify(list));
                if (activeFriendUid === friendUid) {
                    const el = document.getElementById(`status_${msgId}`);
                    if (el) {
                        el.className = `status-mark ${newStatus}`;
                        el.textContent = newStatus === 'read' ? '✓✓' : (newStatus === 'delivered' ? '✓' : 'â˜ï¸');
                    }
                }
            }
        }

        function updateLocalMessagesAsRead(friendUid) {
            const key = `ghost_msgs_${currentUserId}_${friendUid}`;
            const list = getLocalChat(friendUid);
            let updated = false;
            list.forEach(m => {
                if (m.sender === currentUserId && m.status !== 'read') {
                    m.status = 'read';
                    updated = true;
                    if (activeFriendUid === friendUid) {
                        const el = document.getElementById(`status_${m.id}`);
                        if (el) {
                            el.className = `status-mark read`;
                            el.textContent = '✓✓';
                        }
                    }
                }
            });
            if (updated) {
                localStorage.setItem(key, JSON.stringify(list));
            }
        }

        // --- à¦šà§à¦¯à¦¾à¦Ÿ à¦“à¦ªà§‡à¦¨ à¦“ à¦°à§‡à¦¨à§à¦¡à¦¾à¦° ---
        window.openPrivateChat = async (friendUid, friendName, friendGender) => {
            activeFriendUid = friendUid;
            document.getElementById('chatPartnerName').textContent = friendName;
            document.getElementById('chatPartnerAvatar').firstChild.textContent = friendGender === 'female' ? '👩' : '👨';
            document.getElementById('leaveGroupBtn').style.display = 'none';

            const status = userStatusMap.get(friendUid) || 'offline';
            updateChatHeaderPresence(status);

            try {
                if (!aesKeyCache.has(friendUid)) {
                    const friendDoc = await db.collection('users').doc(friendUid).get();
                    if (!friendDoc.exists) return alert('User not found!');
                    const fData = friendDoc.data();
                    if (!fData.publicKey) {
                        return alert('Friend has not generated crypto keys yet. Ask them to login once.');
                    }
                    const key = await computeAESKeyWith(fData.publicKey);
                    aesKeyCache.set(friendUid, key);
                }
            } catch (err) {
                console.error("à¦à¦¨à¦•à§à¦°à¦¿à¦ªà¦¶à¦¨ à¦ªà§à¦°à¦¸à§à¦¤à§à¦¤à¦¿ à¦¤à§à¦°à§à¦Ÿà¦¿:", err);
                return alert("Failed to generate encryption key. Try again.");
            }

            markChatAsRead(friendUid);
            renderLocalChat(friendUid);
            showScreen('chatScreen');
        };

        function renderLocalChat(friendUid) {
            const stream = document.getElementById('chatStream');
            stream.innerHTML = '';
            const list = getLocalChat(friendUid);

            if (list.length === 0) {
                stream.innerHTML = '<div class="empty-placeholder">Start conversation...</div>';
                return;
            }

            list.forEach(m => {
                appendMessageBubble({
                    id: m.id,
                    text: m.text,
                    sender: m.sender === currentUserId ? 'me' : 'stranger',
                    timestamp: m.timestamp,
                    status: m.status
                });
            });
        }

        let activeGroupId = null;
        let activeGroupMembers = [];

        window.openGroupChat = async (g) => {
            activeFriendUid = null;
            activeGroupId = g.id;
            activeGroupMembers = g.members;
            document.getElementById('chatPartnerName').textContent = g.name;
            document.getElementById('chatPartnerAvatar').firstChild.textContent = 'ðŸ‘¥';

            const leaveBtn = document.getElementById('leaveGroupBtn');
            leaveBtn.style.display = 'block';
            leaveBtn.onclick = () => leaveGroup(g.id);

            updateChatHeaderPresence('online');

            markGroupChatAsRead(g.id);
            renderLocalGroupChat(g.id);
            showScreen('chatScreen');
        };

        function renderLocalGroupChat(groupId) {
            const stream = document.getElementById('chatStream');
            stream.innerHTML = '';
            const list = getLocalGroupChat(groupId);

            if (list.length === 0) {
                stream.innerHTML = '<div class="empty-placeholder">Start group conversation...</div>';
                return;
            }

            list.forEach(m => {
                appendMessageBubble({
                    id: m.id,
                    text: m.text,
                    sender: m.sender === currentUserId ? 'me' : 'stranger',
                    timestamp: m.timestamp,
                    status: m.status,
                    senderName: m.senderName
                });
            });
        }

        window.leaveGroup = async (groupId) => {
            if (!confirm('Are you sure you want to leave this group?')) return;
            try {
                const btn = document.getElementById('leaveGroupBtn');
                btn.textContent = 'Leaving...';
                btn.disabled = true;

                await db.collection('groups').doc(groupId).update({
                    members: firebase.firestore.FieldValue.arrayRemove(currentUserId)
                });

                if (client && client.connected) {
                    client.unsubscribe('ghostchat/group/' + groupId);
                }

                alert('You have left the group.');
                showScreen('dashScreen');
                renderChatsTab();
            } catch (e) {
                alert('Failed to leave group: ' + e.message);
            } finally {
                const btn = document.getElementById('leaveGroupBtn');
                if (btn) {
                    btn.textContent = 'Leave';
                    btn.disabled = false;
                }
            }
        };



        function appendMessageBubble({ id, text, sender, timestamp, status, senderName }) {
            const stream = document.getElementById('chatStream');
            const empty = stream.querySelector('.empty-placeholder');
            if (empty) empty.remove();

            const row = document.createElement('div');
            row.className = `bubble-row ${sender}`;
            const time = new Date(timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            let markHtml = '';
            if (sender === 'me') {
                const markChar = status === 'read' ? '✓✓' : (status === 'delivered' ? '✓' : (status === 'mailbox' ? 'â˜ï¸' : 'â³'));
                markHtml = `<span class="status-mark ${status || 'pending'}" id="status_${id}">${markChar}</span>`;
            }

            let nameHtml = '';
            if (senderName && sender === 'stranger') {
                nameHtml = `<div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 2px; margin-left: 12px;">${senderName}</div>`;
            }

            row.innerHTML = `
            ${nameHtml}
            <div class="bubble">${text}</div>
            <div class="bubble-info">
                <span>${time}</span>
                ${markHtml}
            </div>
        `;
            stream.appendChild(row);
            stream.scrollTop = stream.scrollHeight;
        }

        // --- à¦®à§‡à¦¸à§‡à¦œ à¦¸à§‡à¦¨à§à¦¡ à¦“ à¦¸à§à¦®à¦¾à¦°à§à¦Ÿ ACK à¦Ÿà¦¾à¦‡à¦®à¦†à¦‰à¦Ÿ ---
        async function sendMsg() {
            const input = document.getElementById('chatInput');
            const text = input.value.trim();
            if (!text) return;
            if (!activeFriendUid && !activeGroupId) return;

            if (activeGroupId) {
                input.value = '';
                const msgId = 'msg_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6);
                const timestamp = Date.now();

                saveGroupMessageLocally(activeGroupId, {
                    id: msgId, sender: currentUserId, text: text, timestamp: timestamp, status: 'sent', unread: false, senderName: myProfile.name
                });
                appendMessageBubble({ id: msgId, text: text, sender: 'me', timestamp: timestamp, status: 'sent' });

                const payloads = {};
                for (let uid of activeGroupMembers) {
                    if (uid === currentUserId) continue;
                    let aesKey = aesKeyCache.get(uid);
                    if (!aesKey) {
                        const uDoc = await db.collection('users').doc(uid).get();
                        if (uDoc.exists && uDoc.data().publicKey) {
                            aesKey = await computeAESKeyWith(uDoc.data().publicKey);
                            aesKeyCache.set(uid, aesKey);
                        }
                    }
                    if (aesKey) {
                        payloads[uid] = await encryptPayload(text, aesKey);
                    }
                }

                const mqttPayload = {
                    type: 'group_chat',
                    id: msgId,
                    sender: currentUserId,
                    senderName: myProfile.name,
                    groupId: activeGroupId,
                    payloads: payloads,
                    timestamp: timestamp
                };

                client.publish('ghostchat/group/' + activeGroupId, JSON.stringify(mqttPayload));
                
                // âœ… FIX: Group Chat à¦à¦–à¦¨ 100% à¦°à¦¿à¦¯à¦¼à§‡à¦²-à¦Ÿà¦¾à¦‡à¦® à¦à¦¬à¦‚ Ephemeralà¥¤
                // à¦…à¦«à¦²à¦¾à¦‡à¦¨ à¦‡à¦‰à¦œà¦¾à¦°à¦¦à§‡à¦° à¦œà¦¨à§à¦¯ à¦«à¦¾à¦¯à¦¼à¦¾à¦°à¦¬à§‡à¦¸à§‡ à¦•à§‹à¦¨à§‹ Write à¦¹à¦¬à§‡ à¦¨à¦¾à¥¤

                return;
            }

            // --- 1-on-1 Logic ---
            let aesKey = aesKeyCache.get(activeFriendUid);
            if (!aesKey) {
                const friendDoc = await db.collection('users').doc(activeFriendUid).get();
                if (friendDoc.exists && friendDoc.data().publicKey) {
                    aesKey = await computeAESKeyWith(friendDoc.data().publicKey);
                    aesKeyCache.set(activeFriendUid, aesKey);
                }
            }
            if (!aesKey) return alert('Encryption key not activated!');

            input.value = '';
            const msgId = 'msg_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6);
            const timestamp = Date.now();

            saveMessageLocally(activeFriendUid, {
                id: msgId, sender: currentUserId, text: text, timestamp: timestamp, status: 'pending', unread: false
            });
            appendMessageBubble({ id: msgId, text: text, sender: 'me', timestamp: timestamp, status: 'pending' });

            const encrypted = await encryptPayload(text, aesKey);

            client.publish('ghostchat/user/' + activeFriendUid, JSON.stringify({
                type: 'live_chat',
                id: msgId,
                sender: currentUserId,
                senderName: myProfile.name,
                targetUid: activeFriendUid,
                payload: encrypted,
                timestamp: timestamp
            }));

            const timer = setTimeout(async () => {
                pendingAckTimers.delete(msgId);
                try {
                    await db.collection('mailboxes').doc(activeFriendUid).set({
                        messages: firebase.firestore.FieldValue.arrayUnion({
                            id: msgId,
                            sender: currentUserId,
                            payload: encrypted,
                            timestamp: timestamp
                        })
                    }, { merge: true });
                    updateLocalMessageStatus(activeFriendUid, msgId, 'mailbox');
                } catch (e) {
                    console.error("à¦®à§‡à¦‡à¦²à¦¬à¦•à§à¦¸ à¦¬à§à¦¯à¦¾à¦•à¦†à¦ª à¦¬à§à¦¯à¦°à§à¦¥:", e);
                }
            }, 2000);
            pendingAckTimers.set(msgId, timer);
        }

        document.getElementById('sendMsgBtn').addEventListener('click', sendMsg);
        document.getElementById('chatInput').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') sendMsg();
        });

        document.getElementById('backFromChatBtn').addEventListener('click', () => {
            if (activeFriendUid) {
                markChatAsRead(activeFriendUid);
                activeFriendUid = null;
            }
            showScreen('dashScreen');
        });

        // --- à¦ªà§à¦°à§‹à¦«à¦¾à¦‡à¦² à¦®à§à¦¯à¦¾à¦¨à§‡à¦œà¦®à§‡à¦¨à§à¦Ÿ à¦²à¦œà¦¿à¦• ---
        window.copyMyUid = () => {
            if (myProfile && myProfile.uid) {
                navigator.clipboard.writeText(myProfile.uid);
                alert('Your UID has been copied: ' + myProfile.uid);
            }
        };

        window.openMyProfile = () => {
            if (!myProfile) return;
            document.getElementById('editAvatar').innerHTML = renderAvatar(myProfile.avatarUrl, myProfile.gender);
            document.getElementById('editName').value = myProfile.name || '';
            document.getElementById('editBio').value = myProfile.bio || '';
            document.getElementById('editEmail').value = myProfile.email || '';
            document.getElementById('editUid').value = myProfile.uid || '';
            document.getElementById('editPassword').value = myProfile.password || '';
            showScreen('myProfileScreen');
        };

        window.saveMyProfile = async () => {
            const name = document.getElementById('editName').value.trim();
            const bio = document.getElementById('editBio').value.trim();
            const password = document.getElementById('editPassword').value.trim();

            if (!name) return alert('Name cannot be empty!');
            if (password.length < 6) return alert('Password must be at least 6 characters');

            const btn = document.querySelector('#myProfileScreen .btn-submit');
            btn.textContent = 'Saving...';
            btn.disabled = true;

            try {
                let updateData = {
                    name: name,
                    bio: bio,
                    password: password
                };

                // E2EE: Re-encrypt private key if password changes
                if (myProfile && password !== myProfile.password) {
                    const privJwkStr = localStorage.getItem('ghost_priv_key_' + currentUserId);
                    if (privJwkStr) {
                        try {
                            const encResult = await encryptPrivateKey(privJwkStr, password, currentUserId);
                            updateData.encryptedPrivateKey = encResult.encryptedData;
                            updateData.iv = encResult.iv;
                        } catch (e) {
                            console.error("Failed to re-encrypt private key:", e);
                        }
                    }
                }

                await db.collection('users').doc(currentUserId).update(updateData);
                alert('Profile updated successfully!');
                showScreen('dashScreen');
            } catch (e) {
                alert('Update failed: ' + e.message);
            } finally {
                btn.textContent = 'Save';
                btn.disabled = false;
            }
        };

        window.togglePasswordVisibility = () => {
            const passInput = document.getElementById('editPassword');
            if (passInput.type === 'password') {
                passInput.type = 'text';
            } else {
                passInput.type = 'password';
            }
        };

        window.openUserProfile = async (uid) => {
            if (uid === currentUserId) return openMyProfile();
            try {
                const doc = await db.collection('users').doc(uid).get();
                if (!doc.exists) return alert('User not found!');
                const u = doc.data();

                document.getElementById('viewAvatar').innerHTML = renderAvatar(u.avatarUrl, u.gender);
                document.getElementById('viewName').textContent = u.name || 'Unknown';
                document.getElementById('viewCountry').textContent = (u.country || 'Unknown') + ' ' + (flags[u.country] || '');
                document.getElementById('viewGender').textContent = u.gender === 'female' ? '👩 Female' : '👨 Male';

                const uidTextEl = document.getElementById('viewUidText');
                if (uidTextEl) uidTextEl.textContent = u.uid;

                const copyBtn = document.getElementById('copyViewUidBtn');
                if (copyBtn) {
                    copyBtn.onclick = () => {
                        navigator.clipboard.writeText(u.uid);
                        alert('UID has been copied: ' + u.uid);
                    };
                }

                const bioContainer = document.getElementById('bioContainer');
                if (u.bio && u.bio.trim() !== '') {
                    document.getElementById('viewBio').textContent = u.bio;
                    bioContainer.style.display = 'flex';
                } else {
                    bioContainer.style.display = 'none';
                }

                const unfriendCont = document.getElementById('unfriendContainer');
                const unfriendBtn = document.getElementById('unfriendBtn');
                const isFriend = myProfile.friends && myProfile.friends.some(f => f.uid === uid);

                if (isFriend) {
                    unfriendCont.style.display = 'flex';
                    unfriendBtn.onclick = () => unfriendUser(uid);
                } else {
                    unfriendCont.style.display = 'none';
                }

                showScreen('viewProfileScreen');
            } catch (e) {
                console.error(e);
                alert('Failed to load profile: ' + e.message);
            }
        };

        window.unfriendUser = async (targetUid) => {
            if (!confirm('Are you sure you want to unfriend this user?')) return;
            try {
                const btn = document.getElementById('unfriendBtn');
                btn.textContent = 'Unfriending...';
                btn.disabled = true;

                const myFriendList = myProfile.friends || [];
                const myNewFriends = myFriendList.filter(f => f.uid !== targetUid);

                await db.collection('users').doc(currentUserId).update({
                    friends: myNewFriends
                });

                const targetDoc = await db.collection('users').doc(targetUid).get();
                if (targetDoc.exists) {
                    const targetData = targetDoc.data();
                    const targetFriendList = targetData.friends || [];
                    const targetNewFriends = targetFriendList.filter(f => f.uid !== currentUserId);

                    await db.collection('users').doc(targetUid).update({
                        friends: targetNewFriends
                    });
                }

                alert('Unfriended successfully!');
                showScreen('dashScreen');
                renderChatsTab();
                renderFriendsSubTab();
            } catch (e) {
                alert('Failed to unfriend: ' + e.message);
            } finally {
                const btn = document.getElementById('unfriendBtn');
                if (btn) {
                    btn.textContent = 'Unfriend';
                    btn.disabled = false;
                }
            }
        };

        // ============================================================
        // ========== Live TV Chat à¦«à¦¿à¦šà¦¾à¦° (Firebase Live Collection) ===
        // ============================================================

        // Firebase à¦¥à§‡à¦•à§‡ à¦²à¦¾à¦‡à¦­ à¦šà§à¦¯à¦¾à¦¨à§‡à¦² à¦²à§‹à¦¡ à¦•à¦°à§‡ à¦°à§‡à¦¨à§à¦¡à¦¾à¦° à¦•à¦°à¦¬à§‡
        async function loadLiveChannels() {
            const container = document.getElementById('liveChannelsList');
            if (!container) return;

            // âœ… FIX: Session cache â€” à¦à¦•à¦¬à¦¾à¦° load à¦¹à¦²à§‡ à¦†à¦° Firebase hit à¦•à¦°à¦¬à§‡ à¦¨à¦¾
            if (liveChannelsCache !== null) {
                renderLiveChannels(container, liveChannelsCache);
                return;
            }

            try {
                const snap = await db.collection('Live').doc('channels').get();
                const channels = (snap.exists && snap.data().list) ? snap.data().list : [];
                liveChannelsCache = channels; // cache à¦•à¦°à§‡ à¦°à¦¾à¦–à§‹
                renderLiveChannels(container, channels);
            } catch (e) {
                console.error('Live channels load error:', e);
                container.innerHTML = `
                <div class="empty-placeholder" style="grid-column: 1/-1; padding: 40px 0;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">âš ï¸</div>
                    <div>Failed to load channels.</div>
                </div>`;
            }
        }

        // Live channel à¦•à¦¾à¦°à§à¦¡ à¦°à§‡à¦¨à§à¦¡à¦¾à¦° à¦•à¦°à¦¾à¦° helper
        function renderLiveChannels(container, channels) {
            if (!channels || channels.length === 0) {
                container.innerHTML = `
                <div class="empty-placeholder" style="grid-column: 1/-1; padding: 40px 0;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">📺</div>
                    <div>No live channels found.</div>
                    <div style="margin-top: 6px; font-size: 0.75rem;">Add channels from the Admin panel.</div>
                </div>`;
                return;
            }
            const tvEmojis = ['📺', '🎬', 'ðŸ“¡', '🔴', '🎥', 'ðŸ“»'];
            container.innerHTML = channels.map((ch, i) => `
                <div class="live-channel-card" onclick="openLiveChat('${escapeHtml(ch.name)}', '${escapeHtml(ch.url)}')">
                    <div class="live-channel-icon">${tvEmojis[i % tvEmojis.length]}</div>
                    <div class="live-channel-name">${escapeHtml(ch.name)}</div>
                    <div class="live-channel-badge">
                        <span class="live-dot" style="width:5px;height:5px;"></span>
                        LIVE
                    </div>
                </div>
            `).join('');
        }

        // XSS à¦ªà§à¦°à¦¤à¦¿à¦°à§‹à¦§à§‡à¦° à¦œà¦¨à§à¦¯ HTML escape
        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        // à¦²à¦¾à¦‡à¦­ à¦šà§à¦¯à¦¾à¦Ÿ à¦²à¦¿à¦‚à¦• à¦¨à¦¤à§à¦¨ à¦Ÿà§à¦¯à¦¾à¦¬à§‡ à¦“à¦ªà§‡à¦¨ à¦•à¦°à¦¬à§‡
        window.openLiveChat = function (channelName, chatUrl) {
            window.open(chatUrl, '_blank', 'noopener,noreferrer');
        };

        // à¦²à¦¾à¦‡à¦­ à¦­à¦¿à¦‰ à¦¥à§‡à¦•à§‡ à¦¡à§à¦¯à¦¾à¦¶à¦¬à§‹à¦°à§à¦¡à§‡ à¦«à¦¿à¦°à§‡ à¦¯à¦¾à¦¬à§‡ à¦à¦¬à¦‚ iframe src à¦ªà¦°à¦¿à¦·à§à¦•à¦¾à¦° à¦•à¦°à¦¬à§‡
        window.closeLiveView = function () {
            // iframe src à¦ªà¦°à¦¿à¦·à§à¦•à¦¾à¦° à¦•à¦°à¦¾ à¦—à§à¦°à§à¦¤à§à¦¬à¦ªà§‚à¦°à§à¦£ à¦¯à¦¾à¦¤à§‡ à¦¬à§à¦¯à¦¾à¦•à¦—à§à¦°à¦¾à¦‰à¦¨à§à¦¡à§‡ à¦šà¦²à¦¤à§‡ à¦¨à¦¾ à¦¥à¦¾à¦•à§‡
            document.getElementById('liveChatFrame').src = '';
            showScreen('dashScreen');
            // Live à¦Ÿà§à¦¯à¦¾à¦¬à§‡à¦‡ à¦¥à¦¾à¦•à¦¬à§‡
            const liveBtn = document.getElementById('navLiveBtn');
            const allNavItems = document.querySelectorAll('.nav-item');
            allNavItems.forEach(b => b.classList.remove('active'));
            if (liveBtn) liveBtn.classList.add('active');
            const allPanels = document.querySelectorAll('.tab-panel');
            allPanels.forEach(p => p.classList.remove('active'));
            const liveTab = document.getElementById('tabLive');
            if (liveTab) liveTab.classList.add('active');
        };

// --- Avatar Gallery Feature ---
function renderAvatar(avatarUrl, gender) {
    if (avatarUrl) {
        return `<img src="${avatarUrl}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`;
    }
    return gender === 'female' ? '👩' : '👨';
}

let currentAvatarPage = 0;
const AVATARS_PER_PAGE = 50;
const MAX_AVATARS = 100;

window.openAvatarSelector = function() {
    showScreen('avatarSelectionScreen');
    const grid = document.getElementById('avatarGrid');
    const btn = document.getElementById('loadMoreAvatarsBtn');
    if(grid) {
        grid.innerHTML = '';
        currentAvatarPage = 0;
        if(btn) {
            btn.style.display = 'inline-block';
            btn.onclick = () => loadMoreAvatars(grid, btn);
        }
        loadMoreAvatars(grid, btn);
    }
};

function loadMoreAvatars(grid, btn) {
    if(!myProfile) return;
    const isFemale = myProfile.gender === 'female';
    
    // Male: Adventurer style (Cute RPG), Female: Lorelei style (Cute Anime)
    const style = isFemale ? 'lorelei' : 'adventurer';
    const seedPrefix = isFemale ? 'CuteGirl' : 'CoolBoy';
    const bgColors = isFemale ? 'ffdfbf,ffd5dc,ffc0cb,f3e8ff' : 'b6e3f4,c0aede,d1d4f9,e0f2fe';
    
    const startIdx = currentAvatarPage * AVATARS_PER_PAGE + 1;
    let endIdx = startIdx + AVATARS_PER_PAGE - 1;
    
    if (endIdx >= MAX_AVATARS) {
        endIdx = MAX_AVATARS;
        if(btn) btn.style.display = 'none';
    }
    
    for (let i = startIdx; i <= endIdx; i++) {
        const url = `https://api.dicebear.com/7.x/${style}/svg?seed=${seedPrefix}${i}&backgroundColor=${bgColors}`;
        
        const option = document.createElement('div');
        option.className = 'avatar-option';
        option.innerHTML = `<img src="${url}" alt="Avatar">`;
        
        option.onclick = async () => {
            if(!currentUserId) return;
            document.querySelectorAll('.avatar-option').forEach(el => el.classList.remove('selected'));
            option.classList.add('selected');
            
            try {
                await db.collection('users').doc(currentUserId).update({ avatarUrl: url });
                if(myProfile) myProfile.avatarUrl = url;
                
                try {
                    const snap = await db.collection('AggregatedData').doc('all_users').get();
                    if(snap.exists) {
                        let list = snap.data().list || [];
                        const userIdx = list.findIndex(u => u.uid === currentUserId);
                        if(userIdx !== -1) {
                            list[userIdx].avatarUrl = url;
                            await db.collection('AggregatedData').doc('all_users').update({ list: list });
                        }
                    }
                } catch(aggErr) {
                    console.error("Failed to sync aggregated list", aggErr);
                }
                
                updateProfileUI();
                
                setTimeout(() => {
                    showScreen('myProfileScreen');
                    renderChatsTab();
                    loadAllUsers();
                }, 400);
            } catch(e) {
                console.error("Failed to update avatar:", e);
                alert("Failed to update avatar");
            }
        };
        grid.appendChild(option);
    }
    currentAvatarPage++;
}

// --- Random Chat (Anonymous E2EE) Logic ---
window.switchRandomSubTab = function(sub) {
    document.getElementById('pillAllUsersBtn').className = 'sub-pill-btn ' + (sub === 'allUsers' ? 'active' : '');
    document.getElementById('pillRandomChatBtn').className = 'sub-pill-btn ' + (sub === 'randomChat' ? 'active' : '');
    document.getElementById('subAllUsersSection').style.display = sub === 'allUsers' ? 'block' : 'none';
    document.getElementById('subRandomChatSection').style.display = sub === 'randomChat' ? 'block' : 'none';
};

const rndMyId = 'usr_' + Math.random().toString(36).substring(2, 9);
const RND_LOBBY_TOPIC = 'fast_rnd_e2ee_2026/lobby';
const RND_DIRECT_TOPIC = 'fast_rnd_e2ee_2026/user/' + rndMyId;

let rndClient = null;
let rndCurrentRoom = null;
let rndSearchInterval = null;
let rndFallbackTimeout = null;
let rndState = 'INIT';

let rndKeyPair = null;
let rndExportedPubKey = null;
let rndDerivedSharedKey = null;

function updateRndStatus(text, dotClass, title = "Stranger") {
    const peerStatus = document.getElementById('rndPeerStatus');
    const peerTitle = document.getElementById('rndPeerTitle');
    const statusDot = document.getElementById('rndStatusDot');
    if(peerStatus) peerStatus.textContent = text;
    if(peerTitle) peerTitle.textContent = title;
    if(statusDot) statusDot.className = 'rnd-status-dot ' + (dotClass || '');
}

function appendRndSystemPill(text) {
    const hint = document.getElementById('rndEmptyHint');
    if (hint) hint.style.display = 'none';
    const chatBody = document.getElementById('rndChatBody');
    if(!chatBody) return;
    const pill = document.createElement('div');
    pill.className = 'system-pill';
    pill.textContent = text;
    chatBody.appendChild(pill);
    scrollToRndBottom();
}

function appendRndMessage(text, sender) {
    const hint = document.getElementById('rndEmptyHint');
    if (hint) hint.style.display = 'none';
    const chatBody = document.getElementById('rndChatBody');
    if(!chatBody) return;
    const row = document.createElement('div');
    row.className = `bubble-row ${sender}`;
    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    bubble.textContent = text;
    const time = document.createElement('span');
    time.className = 'bubble-time';
    time.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    row.appendChild(bubble);
    row.appendChild(time);
    chatBody.appendChild(row);
    scrollToRndBottom();
}

function scrollToRndBottom() {
    const chatBody = document.getElementById('rndChatBody');
    if(chatBody) {
        requestAnimationFrame(() => {
            chatBody.scrollTop = chatBody.scrollHeight;
        });
    }
}

async function initRndCrypto() {
    rndKeyPair = await window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]
    );
    rndExportedPubKey = await window.crypto.subtle.exportKey("jwk", rndKeyPair.publicKey);
}

async function deriveRndAESKey(peerJwk) {
    const peerKey = await window.crypto.subtle.importKey(
        "jwk", peerJwk, { name: "ECDH", namedCurve: "P-256" }, true, []
    );
    return await window.crypto.subtle.deriveKey(
        { name: "ECDH", public: peerKey },
        rndKeyPair.privateKey,
        { name: "AES-GCM", length: 256 },
        false, ["encrypt", "decrypt"]
    );
}

async function encryptRndPayload(text) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const cipher = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, rndDerivedSharedKey, new TextEncoder().encode(text)
    );
    return { iv: buf2b64(iv), data: buf2b64(cipher) };
}

async function decryptRndPayload(encrypted) {
    const iv = new Uint8Array(b642buf(encrypted.iv));
    const data = b642buf(encrypted.data);
    const dec = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv }, rndDerivedSharedKey, data
    );
    return new TextDecoder().decode(dec);
}

document.addEventListener('DOMContentLoaded', () => {
    // Initialize MQTT for Random Chat
    rndClient = mqtt.connect('wss://broker.emqx.io:8084/mqtt', {
        clientId: rndMyId,
        clean: true
    });

    rndClient.on('connect', async () => {
        await initRndCrypto();
        rndState = 'IDLE';
        updateRndStatus('Ready to connect', '', 'Stranger');
        const btn = document.getElementById('rndActionBtn');
        if(btn) btn.disabled = false;
        rndClient.subscribe(RND_DIRECT_TOPIC);
    });

    rndClient.on('message', async (topic, message) => {
        try {
            const data = JSON.parse(message.toString());

            if (topic === RND_LOBBY_TOPIC && rndState === 'SEARCHING') {
                if (data.type === 'search' && data.id !== rndMyId) {
                    if (rndMyId > data.id) {
                        rndState = 'MATCHED';
                        stopRndSearching();
                        rndDerivedSharedKey = await deriveRndAESKey(data.pubKey);
                        const room = 'fast_rnd_e2ee_2026/room/' + Math.random().toString(36).substring(2, 9);
                        rndClient.publish('fast_rnd_e2ee_2026/user/' + data.id, JSON.stringify({
                            type: 'invite', from: rndMyId, room: room, pubKey: rndExportedPubKey
                        }));
                        joinRndChatRoom(room);
                    }
                }
            }

            if (topic === RND_DIRECT_TOPIC && rndState === 'SEARCHING') {
                if (data.type === 'invite') {
                    rndState = 'MATCHED';
                    stopRndSearching();
                    rndDerivedSharedKey = await deriveRndAESKey(data.pubKey);
                    joinRndChatRoom(data.room);
                }
            }

            if (rndCurrentRoom && topic === rndCurrentRoom) {
                if (data.type === 'peer_ready' && data.id !== rndMyId) {
                    if (rndFallbackTimeout) clearTimeout(rndFallbackTimeout);
                    if (rndState !== 'CONNECTED') markRndConnected();
                }

                if (data.type === 'chat' && data.id !== rndMyId && rndDerivedSharedKey) {
                    try {
                        const plain = await decryptRndPayload(data.payload);
                        appendRndMessage(plain, 'stranger');
                    } catch (err) { console.error(err); }
                }

                if (data.type === 'leave' && data.id !== rndMyId) {
                    appendRndSystemPill('Partner left the chat');
                    updateRndStatus('Disconnected', '', 'Stranger');
                    resetRndToIdle();
                }
            }
        } catch (e) { console.error(e); }
    });

    const rndActionBtn = document.getElementById('rndActionBtn');
    const rndMsgInput = document.getElementById('rndMsgInput');
    const rndSendBtn = document.getElementById('rndSendBtn');

    if(rndActionBtn) rndActionBtn.addEventListener('click', startRndSearch);
    if(rndSendBtn) rndSendBtn.addEventListener('click', sendRndMessage);
    if(rndMsgInput) {
        rndMsgInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') sendRndMessage();
        });
        rndMsgInput.addEventListener('focus', () => setTimeout(scrollToRndBottom, 300));
    }
});

function startRndSearch() {
    cleanRndRoom();
    const chatBody = document.getElementById('rndChatBody');
    if(chatBody) chatBody.innerHTML = '';
    appendRndSystemPill('Searching for a stranger...');
    rndState = 'SEARCHING';
    updateRndStatus('Searching...', 'searching', 'Searching...');

    const btn = document.getElementById('rndActionBtn');
    if(btn) {
        btn.textContent = 'Skip';
        btn.className = 'btn-action skip';
    }
    const input = document.getElementById('rndMsgInput');
    if(input) input.disabled = true;
    const send = document.getElementById('rndSendBtn');
    if(send) send.disabled = true;

    rndClient.subscribe(RND_LOBBY_TOPIC);

    rndSearchInterval = setInterval(() => {
        if (rndState === 'SEARCHING') {
            rndClient.publish(RND_LOBBY_TOPIC, JSON.stringify({
                type: 'search', id: rndMyId, pubKey: rndExportedPubKey
            }));
        }
    }, 1200);
}

function stopRndSearching() {
    if (rndSearchInterval) clearInterval(rndSearchInterval);
    rndClient.unsubscribe(RND_LOBBY_TOPIC);
}

function joinRndChatRoom(room) {
    rndCurrentRoom = room;
    rndClient.subscribe(rndCurrentRoom, () => {
        rndClient.publish(rndCurrentRoom, JSON.stringify({ type: 'peer_ready', id: rndMyId }));
        markRndConnected();
    });

    rndFallbackTimeout = setTimeout(() => {
        if (rndState !== 'CONNECTED') startRndSearch();
    }, 4000);
}

function markRndConnected() {
    rndState = 'CONNECTED';
    updateRndStatus('Online', 'online', 'Stranger');
    appendRndSystemPill('Connection established');
    const input = document.getElementById('rndMsgInput');
    if(input) { input.disabled = false; input.focus(); }
    const send = document.getElementById('rndSendBtn');
    if(send) send.disabled = false;
}

async function sendRndMessage() {
    const input = document.getElementById('rndMsgInput');
    if(!input) return;
    const text = input.value.trim();
    if (text && rndState === 'CONNECTED' && rndCurrentRoom && rndDerivedSharedKey) {
        input.value = '';
        appendRndMessage(text, 'me');
        const payload = await encryptRndPayload(text);
        rndClient.publish(rndCurrentRoom, JSON.stringify({
            type: 'chat', id: rndMyId, payload: payload
        }));
    }
}

function cleanRndRoom() {
    if (rndFallbackTimeout) clearTimeout(rndFallbackTimeout);
    stopRndSearching();
    if (rndCurrentRoom) {
        rndClient.publish(rndCurrentRoom, JSON.stringify({ type: 'leave', id: rndMyId }));
        rndClient.unsubscribe(rndCurrentRoom);
        rndCurrentRoom = null;
    }
    rndDerivedSharedKey = null;
}

function resetRndToIdle() {
    cleanRndRoom();
    rndState = 'IDLE';
    const input = document.getElementById('rndMsgInput');
    if(input) input.disabled = true;
    const send = document.getElementById('rndSendBtn');
    if(send) send.disabled = true;
    const btn = document.getElementById('rndActionBtn');
    if(btn) {
        btn.textContent = 'Next';
        btn.className = 'btn-action';
    }
}

// -----------------------------------------
// NEW SETTINGS, LANGUAGE, DEV CHAT & ABOUT APP LOGIC
// -----------------------------------------

const i18n = {
    en: {
        friends_sub: "Friends",
        requests_sub: "Requests",
        search_sub: "Search",
        create_group: "+ Create Group",
        empty_friends: "Your friend list is empty",
        empty_requests: "No pending friend requests",
        search_placeholder: "Enter UID or Name...",
        search_btn: "Search",
        search_hint: "Search friends by UID or Name",
        nav_random: "Random Users",
        nav_chats: "Chats",
        nav_friends: "Friends",
        nav_live: "Live",
        nav_settings: "Settings",
        settings_title: "Settings",
        language_label: "Language",
        chat_developer: "Chat with Developer",
        about_app: "About this app",
        dev_name: "Developer",
        dev_status: "🟢 Support & Feedback",
        dev_chat_hint: "Send your feedback to the developer...",
        chat_placeholder: "Type a message..."
    },
    bn: {
        friends_sub: "à¦¬à¦¨à§à¦§à§à¦°à¦¾",
        requests_sub: "à¦…à¦¨à§à¦°à§‹à¦§",
        search_sub: "à¦¸à¦¾à¦°à§à¦š à¦•à¦°à§à¦¨",
        create_group: "+ à¦—à§à¦°à§à¦ª à¦¤à§ˆà¦°à¦¿ à¦•à¦°à§à¦¨",
        empty_friends: "à¦†à¦ªà¦¨à¦¾à¦° à¦¬à¦¨à§à¦§à§ à¦¤à¦¾à¦²à¦¿à¦•à¦¾ à¦–à¦¾à¦²à¦¿",
        empty_requests: "à¦•à§‹à¦¨à§‹ à¦«à§à¦°à§‡à¦¨à§à¦¡ à¦°à¦¿à¦•à§‹à§Ÿà§‡à¦¸à§à¦Ÿ à¦¨à§‡à¦‡",
        search_placeholder: "à¦‡à¦‰à¦œà¦¾à¦° à¦†à¦‡à¦¡à¦¿ à¦¬à¦¾ à¦¨à¦¾à¦® à¦²à¦¿à¦–à§à¦¨...",
        search_btn: "à¦¸à¦¾à¦°à§à¦š",
        search_hint: "à¦‡à¦‰à¦œà¦¾à¦° à¦†à¦‡à¦¡à¦¿ à¦¬à¦¾ à¦¨à¦¾à¦® à¦¦à¦¿à§Ÿà§‡ à¦–à§à¦à¦œà§à¦¨",
        nav_random: "à¦°â€à§à¦¯à¦¾à¦¨à§à¦¡à¦® à¦‡à¦‰à¦œà¦¾à¦°",
        nav_chats: "à¦šà§à¦¯à¦¾à¦Ÿà¦¸",
        nav_friends: "à¦¬à¦¨à§à¦§à§à¦°à¦¾",
        nav_live: "à¦²à¦¾à¦‡à¦­",
        nav_settings: "à¦¸à§‡à¦Ÿà¦¿à¦‚à¦¸",
        settings_title: "à¦¸à§‡à¦Ÿà¦¿à¦‚à¦¸",
        language_label: "à¦­à¦¾à¦·à¦¾",
        chat_developer: "à¦¡à§‡à¦­à§‡à¦²à¦ªà¦¾à¦°à§‡à¦° à¦¸à¦¾à¦¥à§‡ à¦•à¦¥à¦¾ à¦¬à¦²à§à¦¨",
        about_app: "à¦…à§à¦¯à¦¾à¦ªà¦Ÿà¦¿ à¦¸à¦®à§à¦ªà¦°à§à¦•à§‡",
        dev_name: "à¦¡à§‡à¦­à§‡à¦²à¦ªà¦¾à¦°",
        dev_status: "🟢 à¦¸à¦¾à¦ªà§‹à¦°à§à¦Ÿ à¦à¦¬à¦‚ à¦«à¦¿à¦¡à¦¬à§à¦¯à¦¾à¦•",
        dev_chat_hint: "à¦¡à§‡à¦­à§‡à¦²à¦ªà¦¾à¦°à¦•à§‡ à¦†à¦ªà¦¨à¦¾à¦° à¦«à¦¿à¦¡à¦¬à§à¦¯à¦¾à¦• à¦ªà¦¾à¦ à¦¾à¦¨...",
        chat_placeholder: "à¦®à§‡à¦¸à§‡à¦œ à¦²à¦¿à¦–à§à¦¨..."
    }
};

function changeLanguage(lang) {
    const dict = i18n[lang];
    if (!dict) return;
    
    localStorage.setItem('ghostchat_lang', lang);
    
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (dict[key]) el.textContent = dict[key];
    });
    
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (dict[key]) el.placeholder = dict[key];
    });
}

function openSettingsSlider() {
    const slider = document.getElementById('settingsSlider');
    if (slider) slider.classList.add('open');
}

function closeSettingsSlider() {
    const slider = document.getElementById('settingsSlider');
    if (slider) slider.classList.remove('open');
}

let unsubscribeDevChat = null;

function openDeveloperChat() {
    closeSettingsSlider();
    showScreen('devChatScreen');
    
    const stream = document.getElementById('devChatStream');
    stream.innerHTML = '<div class="empty-placeholder" data-i18n="dev_chat_hint">' + (document.getElementById('languageSelect').value === 'bn' ? 'à¦¡à§‡à¦­à§‡à¦²à¦ªà¦¾à¦°à¦•à§‡ à¦†à¦ªà¦¨à¦¾à¦° à¦«à¦¿à¦¡à¦¬à§à¦¯à¦¾à¦• à¦ªà¦¾à¦ à¦¾à¦¨...' : 'Send your feedback to the developer...') + '</div>';
    
    // Check and create dev chat document
    if (currentUserId && myProfile) {
        db.collection('feedback_users').doc(currentUserId).set({
            uid: currentUserId,
            name: myProfile.name,
            timestamp: firebase.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        
        if(unsubscribeDevChat) unsubscribeDevChat();
        
        unsubscribeDevChat = db.collection('feedback_users').doc(currentUserId)
            .collection('messages').orderBy('timestamp', 'asc')
            .onSnapshot(snapshot => {
                if(!snapshot.empty) {
                    stream.innerHTML = '';
                    snapshot.forEach(doc => {
                        const m = doc.data();
                        const isMe = m.sender === currentUserId;
                        const row = document.createElement('div');
                        row.className = 'bubble-row ' + (isMe ? 'me' : 'stranger');
                        row.innerHTML = `<div class="bubble">${m.text}</div>`;
                        stream.appendChild(row);
                    });
                    stream.scrollTo(0, stream.scrollHeight);
                }
            });
    }
}

function closeDeveloperChat() {
    if(unsubscribeDevChat) unsubscribeDevChat();
    showScreen('dashScreen');
}

async function sendDevMessage() {
    const input = document.getElementById('devChatInput');
    const text = input.value.trim();
    if(!text || !currentUserId) return;
    
    input.value = '';
    const msgId = Date.now().toString() + Math.floor(Math.random()*1000);
    
    await db.collection('feedback_users').doc(currentUserId)
        .collection('messages').doc(msgId).set({
            id: msgId,
            text: text,
            sender: currentUserId,
            timestamp: firebase.firestore.FieldValue.serverTimestamp()
        });
        
    await db.collection('feedback_users').doc(currentUserId).update({
        lastUpdate: firebase.firestore.FieldValue.serverTimestamp(),
        hasUnread: true // For admin panel indication
    });
}

document.getElementById('devChatInput')?.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') sendDevMessage();
});

async function openAboutApp() {
    const modal = document.getElementById('aboutModal');
    const content = document.getElementById('aboutModalContent');
    content.textContent = 'Loading...';
    modal.classList.add('open');
    
    try {
        const res = await fetch('https://raw.githubusercontent.com/2dgameralif/srhealthcare-resource/refs/heads/main/about_random_chat.txt');
        if(!res.ok) throw new Error('Network error');
        const text = await res.text();
        content.textContent = text;
    } catch(err) {
        content.textContent = "Failed to load instructions. Please check your internet connection.";
    }
}

function closeAboutApp() {
    document.getElementById('aboutModal').classList.remove('open');
}

