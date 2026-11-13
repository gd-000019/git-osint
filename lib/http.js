"use strict";

class ApiError extends Error {
  constructor(status, url, message, retryable = false) {
    super(`HTTP ${status} ${new URL(url).pathname}: ${message || "request failed"}`);
    this.name = "ApiError";
    this.status = status;
    this.url = url;
    this.retryable = retryable;
  }
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function readBounded(response, maximum) {
  const declared = Number(response.headers.get("content-length"));
  if (declared > maximum) throw new Error(`Response exceeds ${maximum} bytes`);
  if (!response.body?.getReader) {
    const text = await response.text();
    if (Buffer.byteLength(text) > maximum) throw new Error(`Response exceeds ${maximum} bytes`);
    return text;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maximum) { await reader.cancel(); throw new Error(`Response exceeds ${maximum} bytes`); }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map(x => Buffer.from(x))).toString("utf8");
}

function createRequester({ headers = {}, timeoutMs = 15000, maxBytes = 5_000_000, retries = 2, fetchImpl = global.fetch, sleepImpl = sleep } = {}) {
  if (typeof fetchImpl !== "function") throw new Error("A fetch implementation is required");
  return async function request(url, options = {}) {
    for (let attempt = 0; attempt <= retries; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let response;
      try {
        response = await fetchImpl(url, { ...options, headers: { ...headers, ...options.headers }, signal: controller.signal });
        const text = await readBounded(response, maxBytes);
        if (response.ok) return text ? JSON.parse(text) : null;
        const rateLimited = response.status === 429 || (response.status === 403 && response.headers.get("x-ratelimit-remaining") === "0");
        const retryable = rateLimited || response.status >= 500;
        if (!retryable || attempt === retries) throw new ApiError(response.status, url, text.slice(0, 250), retryable);
        const retryAfter = Number(response.headers.get("retry-after"));
        const reset = Number(response.headers.get("x-ratelimit-reset"));
        let wait = retryAfter > 0 ? retryAfter * 1000 : 500 * (2 ** attempt);
        if (!retryAfter && reset > 0) wait = Math.max(wait, reset * 1000 - Date.now() + 250);
        await sleepImpl(Math.min(Math.max(wait, 0), 30_000));
      } catch (error) {
        if (error instanceof ApiError) throw error;
        if (attempt === retries || error.name !== "AbortError") throw error;
      } finally { clearTimeout(timer); }
    }
    throw new Error("Request failed after retries");
  };
}

module.exports = { ApiError, createRequester, readBounded };
