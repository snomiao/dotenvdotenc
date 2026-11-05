---
name: payment-provider-selection
description: Choose and wire up a payment provider for a solo developer based in Japan, especially after Stripe refused the account ("business doesn't meet Stripe's terms"). Covers what a Stripe refusal means, why Lemon Squeezy is not an escape from it, merchant-of-record options (Paddle, Patreon) and local processors (KOMOJU, PAY.JP), afdian for Chinese users, the legal pages reviewers expect, and a provider-agnostic checkout + webhook → grant adapter. Use when picking, replacing or adding a payment provider, or when a provider application is refused.
---

# Payment provider selection (solo developer, Japan)

Notes from one case: an individual developer in Japan selling a software subscription, whose Stripe
account was refused. Facts about providers change, so check each provider's official pages before
you rely on anything here. **Do not quote fee numbers from memory.** Link to the pricing pages below.

## Stripe refusal: what it means

- "Your business does not meet Stripe's terms of service", with the review **closed: refused**, is a
  decision about the **business**: its type, model or risk category as Stripe classified it. It
  is not an identity problem.
- Identity or data problems look different. They appear as **verification tasks** in the dashboard
  (upload a document, confirm an address, and so on) and the account stays open while they are pending.
- After a terms refusal, the only path back is an **appeal** to Stripe support. Explain what the
  business sells and how, and point to the live site and legal pages. Opening a new account for the
  same business is not a way around it.
- Assume anything built on Stripe Connect or Stripe-run checkout for this business may hit the same
  classification.

## Options

| option | model | notes |
|---|---|---|
| **Lemon Squeezy** | merchant of record (Stripe-owned) | Japanese businesses were routed to **Stripe Managed Payments**, so the business is reviewed by Stripe again. **Same risk** as the refusal. |
| **Paddle** | merchant of record | Paddle is the seller of record: it handles global sales tax/VAT and invoices. It runs its own domain/business review before live payments. |
| **Patreon** | membership platform (handles payment and tax) | Fits supporter/membership pricing, not per-seat SaaS. Benefits are delivered through Patreon or synced to your app via its API/webhooks. |
| **KOMOJU** | local processor (Japan) | Cards, konbini, Alipay, WeChat Pay and other Japanese and Asian methods. You are the seller: you handle consumption tax and the legal pages. |
| **PAY.JP** | local processor (Japan) | Card payments, with a Stripe-like API. You are the seller. |
| **afdian (爱发电)** | creator-support platform (China) | For Chinese users paying with Alipay or WeChat. Check payout and identity requirements for creators outside mainland China first. |

Rules of thumb:

- **Merchant of record** (Paddle, Patreon, Lemon Squeezy) means less tax and compliance work for a solo
  developer, but you depend on their review and payout rules.
- A **local processor** (KOMOJU, PAY.JP) means Japanese payment methods and a Japanese contract,
  but you carry tax, invoices and the 特商法 page yourself.
- Running two is normal, e.g. an international MoR plus KOMOJU for Japan, or afdian for China.

Official pages, for current fees and availability:

- Stripe: https://stripe.com/pricing
- Paddle: https://www.paddle.com/pricing
- Lemon Squeezy: https://www.lemonsqueezy.com/pricing
- Patreon: https://www.patreon.com/pricing
- KOMOJU: https://komoju.com
- PAY.JP: https://pay.jp
- afdian: https://afdian.com

## Legal pages reviewers expect

Publish these before applying, link them from the site footer and from checkout, and make them
reachable without login:

- **特定商取引法に基づく表記** (Specified Commercial Transactions Act disclosure). Japanese law requires
  it for online sales. It lists seller name, address and phone (an individual may state that they
  will be disclosed without delay on request, under the conditions the law allows), prices, extra
  fees, payment method and timing, delivery timing, and cancellation and refund terms.
- **Terms of service.** What is sold, subscription renewal and cancellation, and acceptable use.
- **Privacy policy.** What is collected, which processors it is shared with (name the payment provider), and how to request deletion.
- **Refund policy.** It must match what the 特商法 page and the provider's own rules say.

Reviewers also look at a working product page with visible prices, a contact method, and a
business description that matches the application.

## Wiring a provider: adapter shape

Keep the app independent of the provider. The app knows **plans** and **grants**, and each provider
only turns a plan into a checkout URL and a webhook into a normalized event.

```ts
interface PaymentProvider {
  id: "paddle" | "komoju" | "payjp" | "patreon" | "afdian";
  createCheckout(input: { userId: string; planId: string; successUrl: string; cancelUrl: string }):
    Promise<{ url: string }>;
  // Verify the signature over the raw body; return null for events you ignore.
  parseWebhook(req: Request): Promise<PaymentEvent | null>;
}

type PaymentEvent = {
  provider: string;
  eventId: string;            // the provider's id, used for idempotency
  kind: "paid" | "renewed" | "refunded" | "canceled";
  userId: string;             // from checkout metadata / custom data, not from the email
  planId: string;
  externalId: string;         // the provider's order/subscription id
  periodEnd?: string;         // ISO
};
```

- **Checkout**: pass `userId` and `planId` in the provider's metadata/custom-data field so the webhook
  can map the payment back without matching emails.
- **Webhook route** (`POST /api/payments/<provider>/webhook`): read the **raw body**, verify the
  signature with `<SITE>_WEBHOOK_SECRET`, `parseWebhook`, then call one shared `applyPaymentEvent`.
- **Grant** (`applyPaymentEvent`): idempotent on `(provider, eventId)` (store processed ids). `paid`/`renewed`
  grants or extends access until `periodEnd`. `refunded`/`canceled` revokes or lets it lapse. The
  grant record keeps `provider` + `externalId` for support and refunds.
- **Success page**: show "processing" and wait for the webhook's grant. Never grant from the
  redirect alone.
- Keys and webhook secrets come from the env (`<SITE>_LIVE_SECRET_KEY`, …), saved with the
  `save-account-credentials` skill. Test end to end in sandbox/test mode before asking for live keys.

Adding a provider then means one adapter, one webhook route and a plan mapping, with no change to
the grant logic.
