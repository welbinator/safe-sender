import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './index.css';
import { initSentry } from './observability.js';

// Initialize Sentry before rendering so React errors are captured from
// the first paint. No-op when VITE_SENTRY_DSN is unset.
initSentry();

// Sprint B C14: Google Identity Services script is loaded statically from
// index.html so CSP can govern it. No more runtime injection.

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
