
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './index.css';

// Load Google Identity Services
const script = document.createElement('script');
script.src = 'https://accounts.google.com/gsi/client';
script.async = true;
script.defer = true;
document.head.appendChild(script);

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
