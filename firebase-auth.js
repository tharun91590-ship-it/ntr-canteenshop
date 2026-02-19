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

  // Set persistence to SESSION so logout works properly
  auth.setPersistence(firebase.auth.Auth.Persistence.SESSION);

  // Disable app verification for local testing
  auth.settings.appVerificationDisabledForTesting = true;

  googleProvider.setCustomParameters({
    prompt: "select_account",
  });

  console.log("✅ Firebase initialized successfully");
} catch (error) {
  console.error("❌ Firebase initialization error:", error);
}

// ================= GLOBAL VARIABLES =================
const ADMIN_EMAIL = "tharun91590@gmail.com";

// ================= UI HELPER FUNCTIONS =================
function showError(message) {
  const errorEl = document.getElementById("errorMessage");
  if (errorEl) {
    errorEl.textContent = message;
    errorEl.style.display = "block";
    const successEl = document.getElementById("successMessage");
    if (successEl) successEl.style.display = "none";
    setTimeout(() => {
      errorEl.style.display = "none";
    }, 3000);
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
    setTimeout(() => {
      successEl.style.display = "none";
    }, 3000);
  } else {
    console.log(message);
  }
}

function showLoading(show) {
  const loadingEl = document.getElementById("loading");
  if (loadingEl) {
    loadingEl.style.display = show ? "block" : "none";
  }
}

function switchTab(tab) {
  const loginTab = document.getElementById("loginTab");
  const registerTab = document.getElementById("registerTab");
  const loginForm = document.getElementById("loginForm");
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
  const strengthBar = document.getElementById("strengthBar");
  const strengthText = document.getElementById("strengthText");

  if (!strengthBar || !strengthText) return;

  let strength = 0;
  if (password.length >= 8) strength += 25;
  if (password.match(/[a-z]+/)) strength += 25;
  if (password.match(/[A-Z]+/)) strength += 25;
  if (password.match(/[0-9]+/)) strength += 25;

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

function sendResetLink() {
  const email = document.getElementById("resetEmail")?.value.trim();

  if (!email) {
    showError("Please enter your email");
    return;
  }

  if (!auth) {
    showError("Firebase not initialized");
    return;
  }

  showLoading(true);

  auth
    .sendPasswordResetEmail(email)
    .then(() => {
      showLoading(false);
      showSuccess("Password reset email sent! Check your inbox.");
      closeForgotPasswordModal();
      if (document.getElementById("resetEmail")) {
        document.getElementById("resetEmail").value = "";
      }
    })
    .catch((error) => {
      showLoading(false);
      handleAuthError(error);
    });
}

async function handleRegistration() {
  if (!auth || !db) {
    showError("Firebase not initialized");
    return;
  }

  const name = document.getElementById("regName")?.value.trim();
  const email = document.getElementById("regEmail")?.value.trim();
  const phone = document.getElementById("regPhone")?.value.trim();
  const password = document.getElementById("regPassword")?.value;
  const confirmPass = document.getElementById("regConfirmPassword")?.value;
  const department = document.getElementById("regDepartment")?.value;
  const address = document.getElementById("regAddress")?.value.trim();
  const preference = document.querySelector('input[name="preference"]:checked');
  const terms = document.getElementById("terms")?.checked;

  if (!name || !email || !phone || !password || !confirmPass) {
    showError("Please fill all required fields");
    return;
  }

  if (!terms) {
    showError("Please accept Terms & Conditions");
    return;
  }

  if (!preference) {
    showError("Please select your food preference");
    return;
  }

  if (password !== confirmPass) {
    showError("Passwords do not match");
    return;
  }

  if (password.length < 6) {
    showError("Password must be at least 6 characters");
    return;
  }

  showLoading(true);

  try {
    const userCredential = await auth.createUserWithEmailAndPassword(
      email,
      password,
    );
    const user = userCredential.user;

    await user.updateProfile({
      displayName: name,
    });

    try {
      await db
        .collection("users")
        .doc(user.uid)
        .set({
          uid: user.uid,
          name: name,
          email: email,
          phone: phone,
          department: department || "Not specified",
          address: address || "",
          preference: preference.value,
          isAdmin: email === ADMIN_EMAIL,
          createdAt: firebase.firestore.FieldValue.serverTimestamp(),
          lastLogin: firebase.firestore.FieldValue.serverTimestamp(),
        });
    } catch (firestoreError) {
      console.warn(
        "Firestore write failed, but user is created:",
        firestoreError,
      );
    }

    showLoading(false);
    showSuccess("Account created successfully! Redirecting...");

    sessionStorage.setItem("user_email", email);
    sessionStorage.setItem("user_name", name);
    sessionStorage.setItem("user_uid", user.uid);
    sessionStorage.setItem(
      "is_admin",
      email === ADMIN_EMAIL ? "true" : "false",
    );
    sessionStorage.setItem("logged_in", "true");

    setTimeout(() => {
      window.location.href = "canteen.html";
    }, 1500);
  } catch (error) {
    showLoading(false);
    handleAuthError(error);
  }
}

async function handleLogin() {
  const email = document.getElementById("loginEmail")?.value.trim();
  const password = document.getElementById("loginPassword")?.value;

  if (!email || !password) {
    showError("Please enter email and password");
    return;
  }

  console.log("Attempting login with:", email);
  showLoading(true);

  try {
    console.log("Calling Firebase signInWithEmailAndPassword...");
    const userCredential = await auth.signInWithEmailAndPassword(
      email,
      password,
    );
    console.log("Firebase response received:", userCredential);

    const user = userCredential.user;
    console.log("User logged in successfully:", user.email, user.uid);

    try {
      await db.collection("users").doc(user.uid).update({
        lastLogin: firebase.firestore.FieldValue.serverTimestamp(),
      });
    } catch (firestoreError) {
      console.warn(
        "Firestore update failed, but login successful:",
        firestoreError,
      );
    }

    let userName = user.displayName || email.split("@")[0];
    let isAdmin = email === ADMIN_EMAIL;

    try {
      const userDoc = await db.collection("users").doc(user.uid).get();
      if (userDoc.exists) {
        const userData = userDoc.data();
        userName = userData?.name || userName;
        isAdmin = userData?.isAdmin || isAdmin;
        console.log("User data from Firestore:", userData);
      }
    } catch (firestoreError) {
      console.warn("Firestore read failed, using defaults:", firestoreError);
    }

    showLoading(false);
    showSuccess("Login successful! Redirecting...");

    sessionStorage.setItem("user_email", email);
    sessionStorage.setItem("user_name", userName);
    sessionStorage.setItem("user_uid", user.uid);
    sessionStorage.setItem("is_admin", isAdmin ? "true" : "false");
    sessionStorage.setItem("logged_in", "true");

    console.log("Session storage set, redirecting to canteen.html");

    setTimeout(() => {
      window.location.href = "canteen.html";
    }, 1500);
  } catch (error) {
    console.error("Login error details:", {
      code: error.code,
      message: error.message,
      stack: error.stack,
    });
    showLoading(false);
    handleAuthError(error);
  }
}

async function googleLogin() {
  showLoading(true);

  if (
    window.location.hostname === "127.0.0.1" ||
    window.location.hostname === "localhost"
  ) {
    console.log("Domain not authorized - showing email login option");
    showLoading(false);
    showError(
      "Google Sign-In not available on localhost. Please use email/password login.",
    );
    return;
  }

  if (!auth || !db || !googleProvider) {
    showError("Firebase not initialized");
    return;
  }

  try {
    const result = await auth.signInWithPopup(googleProvider);
    const user = result.user;

    try {
      const userDoc = await db.collection("users").doc(user.uid).get();

      if (!userDoc.exists) {
        await db
          .collection("users")
          .doc(user.uid)
          .set({
            uid: user.uid,
            name: user.displayName || "Google User",
            email: user.email,
            phone: user.phoneNumber || "",
            department: "Not specified",
            address: "",
            preference: "Not specified",
            isAdmin: user.email === ADMIN_EMAIL,
            createdAt: firebase.firestore.FieldValue.serverTimestamp(),
            lastLogin: firebase.firestore.FieldValue.serverTimestamp(),
          });
      } else {
        await db.collection("users").doc(user.uid).update({
          lastLogin: firebase.firestore.FieldValue.serverTimestamp(),
        });
      }
    } catch (firestoreError) {
      console.warn(
        "Firestore operation failed, but Google login successful:",
        firestoreError,
      );
    }

    showLoading(false);
    showSuccess("Google login successful! Redirecting...");

    sessionStorage.setItem("user_email", user.email);
    sessionStorage.setItem("user_name", user.displayName || "Google User");
    sessionStorage.setItem("user_uid", user.uid);
    sessionStorage.setItem(
      "is_admin",
      user.email === ADMIN_EMAIL ? "true" : "false",
    );
    sessionStorage.setItem("logged_in", "true");

    setTimeout(() => {
      window.location.href = "canteen.html";
    }, 1500);
  } catch (error) {
    showLoading(false);
    handleAuthError(error);
  }
}

function logout() {
  console.log("Logout function called");

  if (!auth) {
    sessionStorage.clear();
    localStorage.removeItem("canteen_users");
    window.location.replace("login.html");
    return;
  }

  showLoading(true);

  auth
    .signOut()
    .then(() => {
      console.log("Firebase sign out successful");
      sessionStorage.clear();
      localStorage.removeItem("canteen_users");
      showLoading(false);
      window.location.replace("login.html");
    })
    .catch((error) => {
      console.error("Logout error:", error);
      sessionStorage.clear();
      localStorage.removeItem("canteen_users");
      window.location.replace("login.html");
    });
}

function initAuthStateListener() {
  if (!auth) return;

  auth.onAuthStateChanged((user) => {
    if (user && window.location.pathname.includes("login.html")) {
      const hasSession = sessionStorage.getItem("logged_in") === "true";

      if (hasSession) {
        console.log(
          "User already logged in with session, redirecting:",
          user.email,
        );
        const isAdmin = user.email === ADMIN_EMAIL;
        sessionStorage.setItem("user_email", user.email);
        sessionStorage.setItem(
          "user_name",
          user.displayName || user.email.split("@")[0],
        );
        sessionStorage.setItem("user_uid", user.uid);
        sessionStorage.setItem("is_admin", isAdmin ? "true" : "false");
        sessionStorage.setItem("logged_in", "true");
        window.location.href = "canteen.html";
      } else {
        console.log("User authenticated but no session, signing out");
        auth.signOut();
      }
    }
  });
}

function handleAuthError(error) {
  console.error("Auth error:", error);

  let errorMessage = "";

  switch (error.code) {
    case "auth/email-already-in-use":
      errorMessage =
        "Email is already registered. Please use a different email or login.";
      break;
    case "auth/invalid-email":
      errorMessage = "Invalid email address format.";
      break;
    case "auth/weak-password":
      errorMessage = "Password is too weak. Please use at least 6 characters.";
      break;
    case "auth/user-not-found":
      errorMessage = "No account found with this email. Please register first.";
      break;
    case "auth/wrong-password":
    case "auth/invalid-credential":
      errorMessage = "Invalid password. Please try again.";
      break;
    case "auth/too-many-requests":
      errorMessage = "Too many failed attempts. Please try again later.";
      break;
    case "auth/user-disabled":
      errorMessage = "This account has been disabled. Contact support.";
      break;
    case "auth/popup-closed-by-user":
      errorMessage = "Sign-in popup was closed. Please try again.";
      break;
    case "auth/popup-blocked":
      errorMessage = "Popup was blocked by your browser. Please allow popups.";
      break;
    case "auth/unauthorized-domain":
      errorMessage =
        "Google Sign-In is not available on this domain. Please use email/password login.";
      break;
    case "permission-denied":
    case "firestore/permission-denied":
      errorMessage = "Database permission error. Please contact support.";
      break;
    default:
      errorMessage = `Authentication failed: ${error.message}`;
  }

  showError(errorMessage);
}

function checkAdminUser() {
  console.log("Checking if admin user exists in Firebase...");
  console.log("Admin email configured as:", ADMIN_EMAIL);

  if (!auth) {
    console.log("Auth not initialized yet");
    return;
  }

  // This is just for debugging - doesn't actually check if user exists
  console.log(
    "To add admin user, go to Firebase Console → Authentication → Users → Add User",
  );
  console.log("Email:", ADMIN_EMAIL);
  console.log("Password: admin123");
}

document.addEventListener("DOMContentLoaded", function () {
  initAuthStateListener();
  checkAdminUser();

  const passwordField = document.getElementById("loginPassword");
  if (passwordField) {
    passwordField.addEventListener("keypress", function (e) {
      if (e.key === "Enter") handleLogin();
    });
  }

  const emailField = document.getElementById("loginEmail");
  if (emailField) {
    emailField.value = ADMIN_EMAIL; // Pre-fill admin email
  }
});

// Make functions globally available
window.switchTab = switchTab;
window.checkPasswordStrength = checkPasswordStrength;
window.showForgotPasswordModal = showForgotPasswordModal;
window.closeForgotPasswordModal = closeForgotPasswordModal;
window.sendResetLink = sendResetLink;
window.handleRegistration = handleRegistration;
window.handleLogin = handleLogin;
window.googleLogin = googleLogin;
window.logout = logout;
