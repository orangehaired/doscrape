const {connect} = require("puppeteer-real-browser");

async function bypassCloudflareAndFetch(targetUrl) {
    const startTime = Date.now();
    try {
        console.log("Target URL:", targetUrl)
        const proxy = process.env.HTTP_PROXY || process.env.HTTPS_PROXY || process.env.http_proxy || process.env.https_proxy;

        console.log("Proxy URL:", proxy);

        let proxyServer, proxyUser, proxyPass;

        if (proxy) {
            const proxyUrl = new URL(proxy);
            proxyServer = `${proxyUrl.protocol}//${proxyUrl.hostname}:${proxyUrl.port}`;
            proxyUser = proxyUrl.username;
            proxyPass = proxyUrl.password;
        }

        console.log(`Using proxy: ${proxyServer || 'No proxy'}`);
        console.log(`Auth: ${proxyUser || ''}:${proxyPass || ''}`);

        const {browser, page} = await connect({
            headless: false,
            turnstile: true,
            args: proxyServer ? [`--proxy-server=${proxyServer}`] : [],
        });

        if (proxyUser && proxyPass) {
            await page.authenticate({
                username: proxyUser,
                password: proxyPass,
            });
        }


        await page.goto(targetUrl, {waitUntil: "networkidle2"});
        console.log("Page loaded, waiting for Cloudflare challenge");

        const cookies = await waitForCookie(page, "EZBookPro.SessionId", {
            timeoutMs: 30000,
            pollMs: 250
        });

        console.log(`Found ${cookies.length} cookies`);

        const hasClearance = cookies.some(c => c.name === "cf_clearance");
        const hasCFBM = cookies.some(c => c.name === "__cf_bm");

        if (!hasClearance) {
            console.warn("cf_clearance cookie not found!");
        } else {
            console.log("cf_clearance cookie found.");
        }

        if (!hasCFBM) {
            console.warn("__cf_bm cookie not found!");
        } else {
            console.log("__cf_bm cookie found.");
        }

        const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join("; ");

        const userAgent = await page.evaluate(() => navigator.userAgent);

        const result = {
            success: true,
            cookies: cookieHeader,
            userAgent: userAgent,
            hasClearance: hasClearance,
            hasCFBM: hasCFBM,
            proxy: proxy || null,
        };

        console.log("Token collection completed successfully");
        console.log(JSON.stringify(result, null, 2));

        await browser.close();

        const totalMs = Date.now() - startTime;
        console.log(`Total time: ${(totalMs / 1000).toFixed(2)} seconds`);
        return result;

    } catch (error) {
        const totalMs = Date.now() - startTime;
        console.log(`Total time before error: ${(totalMs / 1000).toFixed(2)} seconds`);

        console.error("Error during token collection:", error.message);

        const errorResult = {
            success: false,
            error: error.message,
            cookies: "",
            userAgent: "",
            hasClearance: false,
            hasCFBM: false,
            proxy: process.env.HTTP_PROXY || process.env.HTTPS_PROXY || process.env.http_proxy || process.env.https_proxy || null,
            //testResult: null
        };

        console.log(JSON.stringify(errorResult, null, 2));
        return errorResult;
    }
}

const sleep = (ms) => new Promise(res => setTimeout(res, ms));

async function waitForCookie(page, name, opts = {}) {
    const timeoutMs = opts.timeoutMs ?? 20000;
    const pollMs    = opts.pollMs ?? 300;
    const start = Date.now();

    while (Date.now() - start < timeoutMs) {
        const cookies = await page.cookies();
        const found = cookies.find(c => c.name === name);
        if (found) return cookies;

        const jitter = Math.floor(Math.random() * 120);
        await sleep(pollMs + jitter);
    }

    throw new Error(`Timeout waiting for cookie "${name}" after ${timeoutMs} ms`);
}



const TARGET = process.env.TARGET_URL;

if (!TARGET) {
    console.error("TARGET_URL is required. Please provide to me");
    process.exit(1);
}

console.log(`Target URL: ${TARGET}`);
console.log(`HTTP_PROXY: ${process.env.HTTP_PROXY || 'not set'}`);
console.log(`HTTPS_PROXY: ${process.env.HTTPS_PROXY || 'not set'}`);
bypassCloudflareAndFetch(TARGET); 