import "dotenv/config";
import express from "express";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;

const SHOP = process.env.SHOPIFY_SHOP;
const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const API_VERSION = "2026-07";

if (!SHOP || !CLIENT_ID || !CLIENT_SECRET) {
  console.error("Missing SHOPIFY_SHOP, SHOPIFY_CLIENT_ID or SHOPIFY_CLIENT_SECRET");
  process.exit(1);
}

app.use(express.json({ limit: process.env.MAX_BODY_BYTES || "20kb" }));

function safeEqualHex(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

/*
 * Shopify App Proxy signature:
 * - Shopify appends query parameters including shop, timestamp and signature.
 * - Remove signature.
 * - Sort parameter names.
 * - For repeated values, join with commas.
 * - Concatenate key=value pairs WITHOUT '&'.
 * - HMAC-SHA256 using the app client secret.
 */
function verifyAppProxy(req) {
  const params = new URLSearchParams(req.originalUrl.split("?")[1] || "");
  const signature = params.get("signature");
  const timestamp = params.get("timestamp");
  const shop = params.get("shop");

  if (!signature || !timestamp || !shop) return false;
  if (shop !== `${SHOP}.myshopify.com`) return false;

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return false;

  // 10-minute replay window.
  if (Math.abs(Math.floor(Date.now() / 1000) - ts) > 600) return false;

  const grouped = {};
  for (const [key, value] of params.entries()) {
    if (key === "signature") continue;
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(value);
  }

  const message = Object.keys(grouped)
    .sort()
    .map((key) => `${key}=${grouped[key].join(",")}`)
    .join("");

  const calculated = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(message)
    .digest("hex");

  return safeEqualHex(signature, calculated);
}

let cachedToken = null;
let cachedTokenExpiresAt = 0;

async function getAdminAccessToken() {
  const now = Date.now();
  if (cachedToken && now < cachedTokenExpiresAt - 60_000) {
    return cachedToken;
  }

  const tokenUrl = `https://${SHOP}.myshopify.com/admin/oauth/access_token`;
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET
  });

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const data = await response.json();

  if (!response.ok || !data.access_token) {
    console.error("Token error:", data);
    throw new Error("Shopify authentication failed.");
  }

  cachedToken = data.access_token;
  cachedTokenExpiresAt = now + Number(data.expires_in || 86400) * 1000;
  return cachedToken;
}

async function shopifyGraphQL(query, variables) {
  const token = await getAdminAccessToken();
  const response = await fetch(
    `https://${SHOP}.myshopify.com/admin/api/${API_VERSION}/graphql.json`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": token
      },
      body: JSON.stringify({ query, variables })
    }
  );

  const data = await response.json();

  if (!response.ok) {
    console.error("Shopify HTTP error:", data);
    throw new Error("Shopify API request failed.");
  }

  if (data.errors?.length) {
    console.error("Shopify GraphQL errors:", data.errors);
    throw new Error(data.errors[0]?.message || "Shopify GraphQL error.");
  }

  return data.data;
}

app.get("/", (req, res) => {
  res.type("text/plain").send("Shopify COD backend is running.");
});

app.post("/cod-order", async (req, res) => {
  try {
    if (!verifyAppProxy(req)) {
      return res.status(401).json({
        ok: false,
        message: "Invalid Shopify App Proxy signature."
      });
    }

    const {
      variantId,
      quantity,
      name,
      phone,
      city,
      address,
      email = ""
    } = req.body || {};

    const qty = Math.floor(Number(quantity));

    if (!variantId || !Number.isInteger(qty) || qty < 1 || qty > 50) {
      return res.status(400).json({
        ok: false,
        message: "Invalid product or quantity."
      });
    }

    if (!name || name.trim().length < 2) {
      return res.status(400).json({ ok: false, message: "Name is required." });
    }

    if (!phone || phone.trim().length < 7) {
      return res.status(400).json({ ok: false, message: "Phone number is required." });
    }

    if (!city || city.trim().length < 2) {
      return res.status(400).json({ ok: false, message: "City is required." });
    }

    if (!address || address.trim().length < 5) {
      return res.status(400).json({ ok: false, message: "Complete address is required." });
    }

    const normalizedVariantId = String(variantId).startsWith("gid://")
      ? String(variantId)
      : `gid://shopify/ProductVariant/${String(variantId)}`;

    const parts = name.trim().split(/\s+/);
    const firstName = parts.shift();
    const lastName = parts.join(" ");

    const mutation = `#graphql
      mutation CreateCODOrder(
        $order: OrderCreateOrderInput!,
        $options: OrderCreateOptionsInput
      ) {
        orderCreate(order: $order, options: $options) {
          userErrors {
            field
            message
          }
          order {
            id
            name
            displayFinancialStatus
            totalPriceSet {
              shopMoney {
                amount
                currencyCode
              }
            }
          }
        }
      }
    `;

    const variables = {
      order: {
        lineItems: [
          {
            variantId: normalizedVariantId,
            quantity: qty
          }
        ],
        email: email.trim() || undefined,
        customer: {
          toUpsert: {
            firstName,
            lastName: lastName || firstName,
            ...(email.trim() ? { email: email.trim() } : {})
          }
        },
        financialStatus: "PENDING",
        shippingAddress: {
          firstName,
          lastName: lastName || firstName,
          address1: address.trim(),
          city: city.trim(),
          countryCode: "PK",
          phone: phone.trim()
        },
        billingAddress: {
          firstName,
          lastName: lastName || firstName,
          address1: address.trim(),
          city: city.trim(),
          countryCode: "PK",
          phone: phone.trim()
        },
        note: "Cash on Delivery order placed from the storefront COD form.",
        customAttributes: [
          { key: "Payment Method", value: "Cash on Delivery" },
          { key: "Customer Phone", value: phone.trim() },
          { key: "Delivery City", value: city.trim() },
          { key: "Delivery Address", value: address.trim() }
        ]
      },
      options: {
        sendReceipt: false,
        sendFulfillmentReceipt: false
      }
    };

    const data = await shopifyGraphQL(mutation, variables);
    const result = data.orderCreate;

    if (result.userErrors?.length) {
      console.error("Order user errors:", result.userErrors);
      return res.status(400).json({
        ok: false,
        message: result.userErrors.map((e) => e.message).join(" ")
      });
    }

    if (!result.order) {
      return res.status(500).json({
        ok: false,
        message: "Order was not created."
      });
    }

    return res.json({
      ok: true,
      orderName: result.order.name,
      total: result.order.totalPriceSet?.shopMoney?.amount || null,
      currency: result.order.totalPriceSet?.shopMoney?.currencyCode || null
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      ok: false,
      message: "Order could not be created. Please try again."
    });
  }
});

app.listen(PORT, () => {
  console.log(`COD backend running on port ${PORT}`);
});
