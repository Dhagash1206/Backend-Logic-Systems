import { useState, useEffect } from "react";
import PocketBase from "pocketbase";

// Points to the PocketBase backend (see /backend folder)
const pb = new PocketBase("http://127.0.0.1:8090");

export default function App() {
  const [mode, setMode] = useState("login"); // 'login' | 'signup'
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [msg, setMsg] = useState({ text: "", type: "" });
  const [loading, setLoading] = useState(false);
  const [user, setUser] = useState(pb.authStore.model);

  useEffect(() => {
    // Keep local `user` state synced with PocketBase's auth store
    return pb.authStore.onChange(() => setUser(pb.authStore.model));
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMsg({ text: "", type: "" });
    setLoading(true);
    try {
      if (mode === "signup") {
        await pb.collection("users").create({
          email,
          password,
          passwordConfirm: password,
          name,
        });
        await pb.collection("users").authWithPassword(email, password);
        setMsg({ text: "Account created successfully.", type: "success" });
      } else {
        await pb.collection("users").authWithPassword(email, password);
      }
    } catch (err) {
      const detail = err?.data?.data;
      const firstError = detail ? Object.values(detail)[0]?.message : null;
      setMsg({ text: firstError || err.message || "Something went wrong.", type: "error" });
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => pb.authStore.clear();

  // ---------- Logged-in view ----------
  if (user) {
    return (
      <div className="card">
        <div className="avatar">{(user.name || user.email)[0].toUpperCase()}</div>
        <h1>Hi, {user.name || user.email}</h1>
        <p className="subtitle">{user.email}</p>
        <button className="logout" onClick={handleLogout}>Log out</button>
      </div>
    );
  }

  // ---------- Login / Signup view ----------
  const isSignup = mode === "signup";

  return (
    <div className="card">
      <h1>{isSignup ? "Create an account" : "Welcome back"}</h1>
      <p className="subtitle">{isSignup ? "Start your journey with us" : "Sign in to continue"}</p>

      <form onSubmit={handleSubmit}>
        {isSignup && (
          <>
            <label>Full name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Jane Doe" />
          </>
        )}

        <label>Email</label>
        <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />

        <label>Password</label>
        <input type="password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} />

        <button type="submit" disabled={loading}>
          {isSignup ? "Sign up" : "Sign in"}
        </button>
      </form>

      {msg.text && <div className={`msg ${msg.type}`}>{msg.text}</div>}

      <div className="switch">
        {isSignup ? "Already have an account?" : "Don't have an account?"}{" "}
        <a onClick={() => setMode(isSignup ? "login" : "signup")}>
          {isSignup ? "Sign in" : "Sign up"}
        </a>
      </div>
    </div>
  );
}
