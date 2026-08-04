import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "./router";
import App from "./App";
import { captureAccessTokensFromLocation } from "./api";
import "./styles.css";

captureAccessTokensFromLocation();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);
