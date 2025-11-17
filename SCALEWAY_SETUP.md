# Scaleway API Credentials Setup Guide

## Step-by-Step Instructions

### Step 1: Get Your Organization ID

1. Log in to [Scaleway Console](https://console.scaleway.com)
2. Click on your **account/profile icon** (top right corner)
3. Select **"Organization"** from the dropdown
4. Go to **"Settings"** tab
5. Copy the **Organization ID** (format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

**Alternative method:**
- In the console, look at the URL when viewing any resource
- The organization ID is often visible in the navigation or URL

---

### Step 2: Get Your Project ID

1. In Scaleway Console, click on **"Projects"** in the left sidebar
2. Select the project you want to monitor (or create a new one)
3. Click on **"Project Settings"** or **"Settings"**
4. Copy the **Project ID** (format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

**Alternative method:**
- Use Scaleway CLI: `scw project list`
- The Project ID is shown in the list

---

### Step 3: Generate API Keys

1. In Scaleway Console, click on your **account/profile icon** (top right)
2. Select **"Credentials"** → **"API Keys"**
3. Click **"Create API Key"** button
4. Fill in the form:
   - **Name**: `audit-sentinel` (or any descriptive name)
   - **Project**: Select the project you want to monitor
   - **Expiration**: Optional (leave blank for no expiration, or set a date)
5. Click **"Create API Key"**
6. **IMPORTANT**: Copy both values immediately:
   - **Access Key** (starts with `SCW...`)
   - **Secret Key** (long random string)
   - ⚠️ **The Secret Key is shown ONLY ONCE** - save it securely!

---

### Step 4: Set Required IAM Permissions

The API key needs specific permissions to work with Audit Sentinel:

1. In Scaleway Console, go to **"IAM"** → **"Policies"**
2. Find the policy attached to your API key, or create a new one
3. Ensure the policy has these permissions:

**Required Permissions:**
- ✅ **Audit Trail**: `audit:read` (to fetch audit events)
- ✅ **IAM Login Logs**: `iam:read` (to fetch authentication events)
- ✅ **IAM Users**: `iam:write` (for user lock/unlock remediation)
- ✅ **IAM API Keys**: `iam:write` (for API key revocation)

**Quick Setup:**
- If you have **"Full Access"** or **"IAM Manager"** role, you're all set
- For production, create a custom policy with only the above permissions (least privilege)

---

### Step 5: Configure Your Application

#### Option A: Using Docker Compose (Recommended)

1. Create a `.env` file in the project root directory
2. Add your credentials:

```bash
SCALEWAY_API_KEY=your_secret_key_here
SCALEWAY_PROJECT_ID=your_project_id_here
SCALEWAY_ORG_ID=your_organization_id_here
SCALEWAY_API_URL=https://api.scaleway.com
JWT_SECRET=your_jwt_secret_for_api_auth
```

3. Start the application:
```bash
docker compose up -d
```

The `docker-compose.yml` will automatically load these environment variables.

#### Option B: Running Locally (Go binary)

1. Set environment variables in your terminal:

**Windows PowerShell:**
```powershell
$env:SCALEWAY_API_KEY="your_secret_key_here"
$env:SCALEWAY_PROJECT_ID="your_project_id_here"
$env:SCALEWAY_ORG_ID="your_organization_id_here"
$env:SCALEWAY_API_URL="https://api.scaleway.com"
$env:JWT_SECRET="your_jwt_secret"
```

**Windows CMD:**
```cmd
set SCALEWAY_API_KEY=your_secret_key_here
set SCALEWAY_PROJECT_ID=your_project_id_here
set SCALEWAY_ORG_ID=your_organization_id_here
set SCALEWAY_API_URL=https://api.scaleway.com
set JWT_SECRET=your_jwt_secret
```

**Linux/Mac:**
```bash
export SCALEWAY_API_KEY="your_secret_key_here"
export SCALEWAY_PROJECT_ID="your_project_id_here"
export SCALEWAY_ORG_ID="your_organization_id_here"
export SCALEWAY_API_URL="https://api.scaleway.com"
export JWT_SECRET="your_jwt_secret"
```

2. Run the application:
```bash
go run cmd/api/main.go
# or
./api.exe
```

#### Option C: Using .env file (with godotenv)

1. Create a `.env` file in the project root
2. Add your credentials (same format as Option A)
3. The application will automatically load it (using `github.com/joho/godotenv`)

---

### Step 6: Verify Configuration

After starting the application, check the logs to verify:

1. **Check if credentials are loaded:**
   - Look for any startup logs indicating API key status
   - If you see "Fetched X audit events and Y authentication events", it's working!

2. **Test the API:**
   ```bash
   curl http://localhost:8080/health
   ```

3. **Check if real data is coming:**
   - Access the frontend at `http://localhost:3000`
   - View events/alerts - they should show your actual Scaleway account data
   - If you see `user@example.com` or mock data, credentials are not set correctly

---

## Troubleshooting

### Issue: Still seeing mock data

**Solution:**
- Verify environment variables are set correctly
- Check that `SCALEWAY_API_KEY` is the **Secret Key**, not the Access Key
- Restart the application after setting environment variables
- Check application logs for authentication errors

### Issue: "scaleway API authentication failed"

**Solution:**
- Verify the Secret Key is correct (copy-paste again)
- Check that the API key hasn't expired
- Ensure the API key has the required IAM permissions
- Verify Project ID and Organization ID are correct

### Issue: "no events found in response"

**Solution:**
- This might be normal if there are no recent events in your Scaleway account
- Try triggering some activity in Scaleway (login, create resource, etc.)
- Check that Project ID matches the project where activity occurred

### Issue: Environment variables not loading

**Solution:**
- For Docker: Ensure `.env` file is in the same directory as `docker-compose.yml`
- For local: Set variables in the same terminal session before running
- Check for typos in variable names (case-sensitive)

---

## Security Best Practices

1. **Never commit `.env` file to git** - it's already in `.gitignore`
2. **Rotate API keys regularly** (every 90 days recommended)
3. **Use least privilege** - only grant necessary permissions
4. **Store secrets securely** - use secret management tools in production
5. **Monitor API key usage** - check Scaleway console for unusual activity

---

## Quick Reference

| Variable | Description | Where to Find |
|----------|-------------|---------------|
| `SCALEWAY_API_KEY` | Secret Key from API Keys page | Console → Credentials → API Keys |
| `SCALEWAY_PROJECT_ID` | UUID of your project | Console → Projects → Settings |
| `SCALEWAY_ORG_ID` | UUID of your organization | Console → Organization → Settings |
| `SCALEWAY_API_URL` | API endpoint (optional) | Default: `https://api.scaleway.com` |

---

## Need Help?

- Scaleway Documentation: https://www.scaleway.com/en/docs/
- Scaleway API Reference: https://api.scaleway.com/
- Scaleway Support: https://console.scaleway.com/support

