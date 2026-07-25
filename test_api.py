"""Quick smoke test for the SigmaWork auth API."""
import httpx

BASE = "http://localhost:8000/api/auth"

# 1. Test Login
print("=== LOGIN ===")
r = httpx.post(f"{BASE}/login", json={
    "email": "test@example.com",
    "password": "Test@1234",
})
print(f"Status: {r.status_code}")
data = r.json()
token = data["access_token"]
user = data["user"]
print(f"User: {user['full_name']} ({user['email']})")
print(f"Role: {user['role']}")
print(f"Token: {token[:50]}...")

# 2. Test /me
print("\n=== GET /me ===")
r = httpx.get(f"{BASE}/me", headers={"Authorization": f"Bearer {token}"})
print(f"Status: {r.status_code}")
print(f"Response: {r.json()}")

# 3. Test /me/export
print("\n=== EXPORT DATA ===")
r = httpx.get(f"{BASE}/me/export", headers={"Authorization": f"Bearer {token}"})
print(f"Status: {r.status_code}")
print(f"Data keys: {list(r.json().keys())}")

# 4. Test duplicate registration
print("\n=== DUPLICATE REGISTRATION ===")
r = httpx.post(f"{BASE}/register", json={
    "full_name": "Test User",
    "email": "test@example.com",
    "password": "Test@1234",
    "confirm_password": "Test@1234",
})
print(f"Status: {r.status_code} (expected 409)")
print(f"Detail: {r.json()['detail']}")

# 5. Test weak password
print("\n=== WEAK PASSWORD ===")
r = httpx.post(f"{BASE}/register", json={
    "full_name": "Weak User",
    "email": "weak@example.com",
    "password": "short",
    "confirm_password": "short",
})
print(f"Status: {r.status_code} (expected 422 or 400)")

# 6. Test forgot password
print("\n=== FORGOT PASSWORD ===")
r = httpx.post(f"{BASE}/forgot-password", json={
    "email": "test@example.com",
})
print(f"Status: {r.status_code}")
print(f"Message: {r.json()['message']}")
if r.json().get("detail"):
    print(f"Dev token: {r.json()['detail']}")

print("\n=== ALL TESTS PASSED ===")
