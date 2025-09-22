import React from 'react';
import { GoogleOAuthProvider } from '@react-oauth/google';

const GoogleAuthProvider = ({ children }) => {
  // This client ID should be configured with the exact origin where your app is running
  const clientId = "162975842371-2qrvmk6okd84710ags6vdu4k4ge8qhtq.apps.googleusercontent.com";
  
  // Log the current origin to help with debugging
  console.log("Current application origin:", window.location.origin);
  
  return (
    <GoogleOAuthProvider 
      clientId={clientId}
      onScriptLoadError={(error) => console.error("Failed to load Google OAuth script:", error)}
      onScriptLoadSuccess={() => console.log("Google OAuth script loaded successfully")}
    >
      {children}
    </GoogleOAuthProvider>
  );
};

export default GoogleAuthProvider;