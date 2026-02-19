// ================= FIREBASE CONFIGURATION =================
const firebaseConfig = {
  apiKey: "AIzaSyB6f-LHiZTRqwIrzf3bQRd10vOmnOu_ors",
  authDomain: "ntr-canteen-vibe.firebaseapp.com",
  projectId: "ntr-canteen-vibe",
  storageBucket: "ntr-canteen-vibe.firebasestorage.app",
  messagingSenderId: "768512253825",
  appId: "1:768512253825:web:dfe5dbc8d0924a8c189280",
  measurementId: "G-P6QED7VFK5",
};

// ================= INITIALIZE FIREBASE =================
let auth, db, googleProvider;

try {
  firebase.initializeApp(firebaseConfig);
  auth = firebase.auth();
  db = firebase.firestore();
  googleProvider = new firebase.auth.GoogleAuthProvider();

  // SESSION persistence: user is logged out when tab closes
  auth.setPersistence(firebase.auth.Auth.Persistence.SESSION);

  // FIX: Removed appVerificationDisabledForTesting — not safe for production

  googleProvider.setCustomParameters({ prompt: "select_account" });

  console.log("✅ Firebase initialized successfully");
} catch (error) {
  console.error("❌ Firebase initialization error:", error);
}

// ================= GLOBAL VARIABLES =================
// FIX: Admin email kept for role-checking only — password never stored here
const ADMIN_EMAIL = "tharun91590@gmail.com";

// ================= UI HELPER FUNCTIONS =================
function showError(message) {
  const errorEl = document.getElementById("errorMessage");
  if (errorEl) {
    errorEl.textContent = message;
    errorEl.style.display = "block";
    const successEl = document.getElementById("successMessage");
    if (successEl) successEl.style.display = "none";
    setTimeout(() => { errorEl.style.display = "none"; }, 4000);
  } else {
    alert(message);
  }
}

function showSuccess(message) {
  const successEl = document.getElementById("successMessage");
  if (successEl) {
    successEl.textContent = message;
    successEl.style.display = "block";
    const errorEl = document.getElementById("errorMessage");
    if (errorEl) errorEl.style.display = "none";
    setTimeout(() => { successEl.style.display = "none"; }, 4000);
  } else {
    console.log(message);
  }
}

function showLoading(show) {
  const loadingEl = document.getElementById("loading");
  if (loadingEl) loadingEl.style.display = show ? "block" : "none";
}

function switchTab(tab) {
  const loginTab    = document.getElementById("loginTab");
  const registerTab = document.getElementById("registerTab");
  const loginForm   = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");

  if (tab === "login") {
    loginTab.classList.add("active");
    registerTab.classList.remove("active");
    loginForm.classList.add("active");
    registerForm.classList.remove("active");
  } else {
    registerTab.classList.add("active");
    loginTab.classList.remove("active");
    registerForm.classList.add("active");
    loginForm.classList.remove("active");
  }
}

function checkPasswordStrength() {
  const password = document.getElementById("regPassword")?.value || "";
  const strengthBar  = document.getElementById("strengthBar");
  const strengthText = document.getElementById("strengthText");
  if (!strengthBar || !strengthText) return;

  let strength = 0;
  if (password.length >= 8)        strength += 25;
  if (password.match(/[a-z]+/))    strength += 25;
  if (password.match(/[A-Z]+/))    strength += 25;
  if (password.match(/[0-9]+/))    strength += 25;

  strengthBar.style.width = strength + "%";

  if (strength <= 25) {
    strengthBar.style.background = "#e53935";
    strengthText.textContent = "Password strength: Weak";
  } else if (strength <= 50) {
    strengthBar.style.background = "#fb8c00";
    strengthText.textContent = "Password strength: Fair";
  } else if (strength <= 75) {
    strengthBar.style.background = "#2196f3";
    strengthText.textContent = "Password strength: Good";
  } else {
    strengthBar.style.background = "#4caf50";
    strengthText.textContent = "Password strength: Strong";
  }
}

function showForgotPasswordModal() {
  const modal = document.getElementById("forgotPasswordModal");
  if (modal) modal.classList.add("active");
}

function closeForgotPasswordModal() {
  const modal = document.getElementById("forgotPasswordModal");
  if (modal) modal.classList.remove("active");
}

// ================= PASSWORD RESET =================
function sendResetLink() {
  const email = document.getElementById("resetEmail")?.value.trim();
  if (!email) { showError("Please enter your email"); return; }
  if (!auth)  { showError("Firebase not initialized"); return; }

  showLoading(true);
  auth.sendPasswordResetEmail(email)
    .then(() => {
      showLoading(false);
      showSuccess("Password reset email sent! Check your inbox.");
      closeForgotPasswordModal();
      document.getElementById("resetEmail").value = "";
    })
    .catch((error) => {
      showLoading(false);
      handleAuthError(error);
    });
}

// ================= REGISTRATION =================
async function handleRegistration() {
  if (!auth || !db) { showError("Firebase not initialized"); return; }

  const name        = document.getElementById("regName")?.value.trim();
  const email       = document.getElementById("regEmail")?.value.trim();
  const phone       = document.getElementById("regPhone")?.value.trim();
  const password    = document.getElementById("regPassword")?.value;
  const confirmPass = document.getElementById("regConfirmPassword")?.value;
  const department  = document.getElementById("regDepartment")?.value;
  const address     = document.getElementById("regAddress")?.value.trim();
  const preference  = document.querySelector('input[name="preference"]:checked');
  const terms       = document.getElementById("terms")?.checked;

  // Validation
  if (!name || !email || !phone || !password || !confirmPass) {
    showError("Please fill all required fields"); return;
  }
  if (!terms) {
    showError("Please accept Terms & Conditions"); return;
  }
  if (!preference) {
    showError("Please select your food preference"); return;
  }
  if (password !== confirmPass) {
    showError("Passwords do not match"); return;
  }
  if (password.length < 6) {
    showError("Password must be at least 6 characters"); return;
  }

  showLoading(true);

  try {
    const userCredential = await auth.createUserWithEmailAndPassword(email, password);
    const user = userCredential.user;

    await user.updateProfile({ displayName: name });

    try {
      await db.collection("users").doc(user.uid).set({
        uid:        user.uid,
        name:       name,
        email:      email,
        phone:      phone,
        department: department || "Not specified",
        address:    address || "",
        preference: preference.value,
        isAdmin:    email === ADMIN_EMAIL,
        createdAt:  firebase.firestore.FieldValue.serverTimestamp(),
        lastLogin:  firebase.firestore.FieldValue.serverTimestamp(),
      });
    } catch (firestoreError) {
      console.warn("Firestore write failed, but user is created:", firestoreError);
    }

    showLoading(false);
    showSuccess("Account created successfully! Redirecting...");
    setSession(user, name, email === ADMIN_EMAIL);

    setTimeout(() => { window.location.href = "canteen.html"; }, 1500);
  } catch (error) {
    showLoading(false);
    handleAuthError(error);
  }
}

// ================= LOGIN =================
async function handleLogin() {
  const email    = document.getElementById("loginEmail")?.value.trim();
  const password = document.getElementById("loginPassword")?.value;

  if (!email || !password) {
    showError("Please enter email and password"); return;
  }
  if (!auth) {
    showError("Firebase not initialized"); return;
  }

  showLoading(true);

  try {
    const userCredential = await auth.signInWithEmailAndPassword(email, password);
    const user = userCredential.user;

    // Update last login timestamp (non-blocking)
    db.collection("users").doc(user.uid)
      .update({ lastLogin: firebase.firestore.FieldValue.serverTimestamp() })
      .catch((e) => console.warn("Firestore lastLogin update failed:", e));

    let userName = user.displayName || email.split("@")[0];
    let isAdmin  = email === ADMIN_EMAIL;

    // Try to get extra user data from Firestore
    try {
      const userDoc = await db.collection("users").doc(user.uid).get();
      if (userDoc.exists) {
        const userData = userDoc.data();
        userName = userData?.name || userName;
        isAdmin  = userData?.isAdmin || isAdmin;
      }
    } catch (firestoreError) {
      console.warn("Firestore read failed, using defaults:", firestoreError);
    }

    showLoading(false);
    showSuccess("Login successful! Redirecting...");
    setSession(user, userName, isAdmin);

    setTimeout(() => { window.location.href = "canteen.html"; }, 1500);
  } catch (error) {
    showLoading(false);
    handleAuthError(error);
  }
}

// ================= GOOGLE LOGIN =================
async function googleLogin() {
  if (!auth || !db || !googleProvider) {
    showError("Firebase not initialized"); return;
  }

  showLoading(true);

  try {
    const result = await auth.signInWithPopup(googleProvider);
    const user   = result.user;

    try {
      const userDoc = await db.collection("users").doc(user.uid).get();
      if (!userDoc.exists) {
        await db.collection("users").doc(user.uid).set({
          uid:        user.uid,
          name:       user.displayName || "Google User",
          email:      user.email,
          phone:      user.phoneNumber || "",
          department: "Not specified",
          address:    "",
          preference: "Not specified",
          isAdmin:    user.email === ADMIN_EMAIL,
          createdAt:  firebase.firestore.FieldValue.serverTimestamp(),
          lastLogin:  firebase.firestore.FieldValue.serverTimestamp(),
        });
      } else {
        await db.collection("users").doc(user.uid)
          .update({ lastLogin: firebase.firestore.FieldValue.serverTimestamp() });
      }
    } catch (firestoreError) {
      console.warn("Firestore operation failed, but Google login successful:", firestoreError);
    }

    showLoading(false);
    showSuccess("Google login successful! Redirecting...");
    setSession(user, user.displayName || "Google User", user.email === ADMIN_EMAIL);

    setTimeout(() => { window.location.href = "canteen.html"; }, 1500);
  } catch (error) {
    showLoading(false);
    handleAuthError(error);
  }
}

// ================= LOGOUT =================
function logout() {
  if (!auth) {
    clearSession();
    window.location.replace("login.html");
    return;
  }

  showLoading(true);
  auth.signOut()
    .then(() => {
      clearSession();
      showLoading(false);
      window.location.replace("login.html");
    })
    .catch((error) => {
      console.error("Logout error:", error);
      clearSession();
      window.location.replace("login.html");
    });
}

// ================= SESSION HELPERS =================
// FIX: Centralised session management — no duplication across functions
function setSession(user, userName, isAdmin) {
  sessionStorage.setItem("user_email", user.email);
  sessionStorage.setItem("user_name",  userName);
  sessionStorage.setItem("user_uid",   user.uid);
  sessionStorage.setItem("is_admin",   isAdmin ? "true" : "false");
  sessionStorage.setItem("logged_in",  "true");
}

function clearSession() {
  sessionStorage.clear();
  localStorage.removeItem("canteen_users");
}

// ================= AUTH STATE LISTENER =================
// FIX: Simplified logic — only auto-redirect if session is active
function initAuthStateListener() {
  if (!auth) return;

  auth.onAuthStateChanged((user) => {
    const onLoginPage = window.location.pathname.includes("login.html") ||
                        window.location.pathname === "/" ||
                        window.location.pathname.endsWith("index.html");

    if (user && onLoginPage) {
      const hasSession = sessionStorage.getItem("logged_in") === "true";
      if (hasSession) {
        // Already logged in — send to app
        window.location.href = "canteen.html";
      } else {
        // Firebase still has a session but we don't — sign out cleanly
        auth.signOut();
      }
    }
  });
}

// ================= ERROR HANDLER =================
function handleAuthError(error) {
  console.error("Auth error:", error.code, error.message);

  const messages = {
    "auth/email-already-in-use":   "Email is already registered. Please log in instead.",
    "auth/invalid-email":          "Invalid email address format.",
    "auth/weak-password":          "Password is too weak. Use at least 6 characters.",
    "auth/user-not-found":         "No account found with this email. Please register first.",
    "auth/wrong-password":         "Incorrect password. Please try again.",
    "auth/invalid-credential":     "Incorrect email or password. Please try again.",
    "auth/too-many-requests":      "Too many failed attempts. Please try again later.",
    "auth/user-disabled":          "This account has been disabled. Contact support.",
    "auth/popup-closed-by-user":   "Sign-in popup was closed. Please try again.",
    "auth/popup-blocked":          "Popup was blocked by your browser. Please allow popups.",
    "auth/unauthorized-domain":    "This domain is not authorised in Firebase. Add it in Firebase Console → Authentication → Authorized Domains.",
    "permission-denied":           "Database permission error. Please contact support.",
    "firestore/permission-denied": "Database permission error. Please contact support.",
  };

  showError(messages[error.code] || `Authentication failed: ${error.message}`);
}

// ================= INIT =================
document.addEventListener("DOMContentLoaded", function () {
  initAuthStateListener();

  // FIX: Removed hardcoded credential pre-fill
  // Enter key submits login form
  document.getElementById("loginPassword")?.addEventListener("keypress", function (e) {
    if (e.key === "Enter") handleLogin();
  });
  document.getElementById("loginEmail")?.addEventListener("keypress", function (e) {
    if (e.key === "Enter") handleLogin();
  });
});

// ================= GLOBAL EXPORTS =================
window.switchTab              = switchTab;
window.checkPasswordStrength  = checkPasswordStrength;
window.showForgotPasswordModal = showForgotPasswordModal;
window.closeForgotPasswordModal = closeForgotPasswordModal;
window.sendResetLink          = sendResetLink;
window.handleRegistration     = handleRegistration;
window.handleLogin            = handleLogin;
window.googleLogin            = googleLogin;
window.logout                 = logout;
