/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        xbg: "#0b0f19",
        xcard: "#111827",
        xblue: "#0ea5e9",
        xgold: "#fbbf24",
        xmuted: "#94a3b8"
      }
    }
  },
  plugins: []
};
