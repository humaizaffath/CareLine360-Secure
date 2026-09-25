// Fired on same-tab auth changes so AuthContext stays in sync
// (the native "storage" event only fires in other tabs).
export const AUTH_CHANGE_EVENT = "auth-change";
const notify = () => window.dispatchEvent(new Event(AUTH_CHANGE_EVENT));

export const setAuth = ({ accessToken, refreshToken, user }) => {
  localStorage.setItem("accessToken", accessToken);
  localStorage.setItem("refreshToken", refreshToken);
  localStorage.setItem("role", user.role);
  localStorage.setItem("userId", user.id);
  localStorage.setItem("fullName", user.fullName || "");
  notify();
};

export const clearAuth = () => {
  localStorage.removeItem("accessToken");
  localStorage.removeItem("refreshToken");
  localStorage.removeItem("role");
  localStorage.removeItem("userId");
  localStorage.removeItem("fullName");
  notify();
};

export const getRole = () => localStorage.getItem("role");
export const getFullName = () => localStorage.getItem("fullName");
export const hasToken = () => !!localStorage.getItem("accessToken");
