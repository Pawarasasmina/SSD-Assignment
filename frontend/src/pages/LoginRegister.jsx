import React, { useState } from "react";
import axios from "axios";
import { useUserSession } from "../components/UserSession"; // Import the useUserSession hook
import { GoogleLogin } from '@react-oauth/google';
import { jwtDecode } from 'jwt-decode';
import {
  FaGooglePlusG,
  FaFacebookF,
  FaGithub,
  FaLinkedinIn,
  FaEnvelope,
  FaLock,
  FaPhone,
  FaUser,
} from "react-icons/fa";
import styles from "../styles/LoginRegister.module.css";

export const LoginRegister = () => {
  const [isRegistering, setIsRegistering] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
    phone: "",
  });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const { setUser } = useUserSession(); // Use the hook to get setUser

  const handleToggle = () => {
    setIsRegistering(!isRegistering);
    setFormData({
      name: "",
      email: "",
      password: "",
      confirmPassword: "",
      phone: "",
    });
    setError("");
    setSuccess("");
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    const { name, email, password, confirmPassword, phone } = formData;

    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    try {
      const response = await axios.post(
        "http://localhost:3000/api/users/register",
        { name, email, password, phone }
      );
      setSuccess("User registered successfully!");
      setError("");
    } catch (err) {
      setError(err.response?.data?.message || "Registration failed");
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    const { email, password } = formData;

    try {
      const response = await axios.post(
        "http://localhost:3000/api/users/login",
        { email, password }
      );

      const { token, user: loggedInUser } = response.data;

      // Check if shopId exists in the response
      console.log(loggedInUser); // Ensure that shopId is present in the loggedInUser object

      // Store token
      localStorage.setItem("token", token);

      // Update user state using the UserSession hook
      setUser(loggedInUser);

      // Redirect based on user level
      if (loggedInUser.userLevel === 2) {
        window.location.href = "/adminDashboard";
      } else if (loggedInUser.userLevel === 1) {
        window.location.href = "/overview";
      } else {
        window.location.href = "/home";
      }

      setSuccess("Login successful!");
      setError("");
    } catch (err) {
      setError(err.response?.data?.message || "Login failed");
    }
  };

    // Handler for both Google login and signup
  const handleGoogleLogin = async (credentialResponse) => {
    try {
      console.log("Google auth success, credential received:", credentialResponse);
      
      if (!credentialResponse.credential) {
        setError("Failed to get credentials from Google");
        return;
      }
      
      // Decode the credential to get user info for debug purposes
      const decoded = jwtDecode(credentialResponse.credential);
      console.log("Decoded Google credential:", decoded);
      
      // Send the token to your backend for verification
      // The backend will handle both new registrations and existing user logins
      const response = await axios.post('http://localhost:3000/api/users/google-auth', {
        token: credentialResponse.credential,
        isRegistering: isRegistering // Tell backend if this is coming from register form
      });
      
      console.log("Backend response:", response.data);
      
      const { token, user: loggedInUser } = response.data;
      
      // Store token
      localStorage.setItem("token", token);
      
      // Update user state
      setUser(loggedInUser);
      
      // Redirect based on user level
      if (loggedInUser.userLevel === 2) {
        window.location.href = "/adminDashboard";
      } else if (loggedInUser.userLevel === 1) {
        window.location.href = "/overview";
      } else {
        window.location.href = "/home";
      }
      
      const successMessage = isRegistering && response.data.isNewUser
        ? "Registration successful! You are now logged in." 
        : "Login successful!";
      
      setSuccess(successMessage);
      setError("");
    } catch (err) {
      console.error("Google auth error:", err);
      
      // Handle specific error for existing account during registration
      if (err.response?.status === 400 && err.response?.data?.accountExists && isRegistering) {
        setError("An account with this Google email already exists. Please use the Sign In form instead.");
        // Optionally, switch to login form
        setTimeout(() => {
          setIsRegistering(false);
        }, 2000);
      } else {
        // Generic error handling
        const errorMsg = err.response?.data?.message || err.message || "Google authentication failed";
        setError(errorMsg);
      }
      setError(errorMsg);
    }
  };

  return (
    <div className={styles["login-register-page"]}>
      <div
        className={`${styles["container"]} ${
          isRegistering ? styles.active : ""
        }`}
      >
        {/* Sign In Form */}
        <div
          className={`${styles["form-container"]} ${styles["sign-in"]} ${
            isRegistering ? styles.hidden : ""
          }`}
        >
          <form onSubmit={handleLogin}>
            <h1>Sign In</h1>
            <div className={styles["social-container"]}>
              <GoogleLogin
                onSuccess={handleGoogleLogin}
                onError={(error) => {
                  console.error("Google login error:", error);
                  setError("Google login failed. Please try again.");
                }}
                useOneTap={false}
                theme="filled_blue"
                text="signin_with"
                shape="rectangular"
                size="medium"
              />
            </div>
            <span>or use your email and password</span>
            <div
              className={`${styles["inputGroup"]} ${styles["sign-in-input"]}`}
            >
              <FaEnvelope className={styles.icon} />
              <input
                type="email"
                name="email"
                placeholder="Email"
                value={formData.email}
                onChange={handleChange}
                required
              />
            </div>
            <div
              className={`${styles["inputGroup"]} ${styles["sign-in-input"]}`}
            >
              <FaLock className={styles.icon} />
              <input
                type="password"
                name="password"
                placeholder="Password"
                value={formData.password}
                onChange={handleChange}
                required
              />
            </div>
            <a href="#">Forget Your Password?</a>
            <button type="submit">Sign In</button>
            {error && <div className={styles.error}>{error}</div>}
            {success && <div className={styles.success}>{success}</div>}
          </form>
        </div>

        {/* Sign Up Form */}
        <div
          className={`${styles["form-container"]} ${styles["sign-up"]} ${
            isRegistering ? "" : styles.hidden
          }`}
        >
          <form onSubmit={handleRegister}>
            <h1>Sign Up</h1>
            <div className={styles["social-container"]}>
              <GoogleLogin
                onSuccess={handleGoogleLogin}
                onError={(error) => {
                  console.error("Google login error:", error);
                  setError("Google login failed. Please try again.");
                }}
                useOneTap={false}
                theme="filled_blue"
                text="signup_with"
                shape="rectangular"
                size="medium"
              />
            </div>
            <span>or sign up with email</span>
            <div
              className={`${styles["inputGroup"]} ${styles["sign-up-input"]}`}
            >
              <FaUser className={styles.icon} />
              <input
                type="text"
                name="name"
                placeholder="Enter Your Name"
                value={formData.name}
                onChange={handleChange}
                required
              />
            </div>
            <div
              className={`${styles["inputGroup"]} ${styles["sign-up-input"]}`}
            >
              <FaPhone className={styles.icon} />
              <input
                type="tel"
                name="phone"
                placeholder="Enter Your Mobile Number"
                value={formData.phone}
                onChange={handleChange}
                required
              />
            </div>
            <div
              className={`${styles["inputGroup"]} ${styles["sign-up-input"]}`}
            >
              <FaEnvelope className={styles.icon} />
              <input
                type="email"
                name="email"
                placeholder="Enter Your E-Mail"
                value={formData.email}
                onChange={handleChange}
                required
              />
            </div>
            <div
              className={`${styles["inputGroup"]} ${styles["sign-up-input"]}`}
            >
              <FaLock className={styles.icon} />
              <input
                type="password"
                name="password"
                placeholder="Enter a Password"
                value={formData.password}
                onChange={handleChange}
                required
              />
            </div>
            <div
              className={`${styles["inputGroup"]} ${styles["sign-up-input"]}`}
            >
              <FaLock className={styles.icon} />
              <input
                type="password"
                name="confirmPassword"
                placeholder="Confirm Password"
                value={formData.confirmPassword}
                onChange={handleChange}
                required
              />
            </div>
            <button type="submit" className={styles.submitButton}>
              Finish
            </button>
            {error && <div className={styles.error}>{error}</div>}
            {success && <div className={styles.success}>{success}</div>}
          </form>
        </div>

        {/* Toggle Panel */}
        <div
          className={`${styles["toggle-container"]} ${
            isRegistering ? styles.active : ""
          }`}
        >
          <div className={styles.toggle}>
            <div
              className={`${styles["toggle-panel"]} ${styles["toggle-left"]}`}
            >
              <h1>Welcome Back!</h1>
              <p>
                Enter your personal details to use all of the site's features
              </p>
              <button onClick={handleToggle}>Sign In</button>
            </div>
            <div
              className={`${styles["toggle-panel"]} ${styles["toggle-right"]}`}
            >
              <h1>Hello, Friend!</h1>
              <p>
                Register with your personal details to use all of the site's
                features
              </p>
              <button onClick={handleToggle}>Sign Up</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
