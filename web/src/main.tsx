import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Inbox } from "./Inbox";
import "./style.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Inbox />
  </StrictMode>,
);
