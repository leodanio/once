import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import {
  CHUNK_SIZE_BYTES,
  MAX_FILE_SIZE_BYTES,
  deriveChunkIv,
  buildChunkAad,
  generateFileKey,
  exportRawKey,
  importRawFileKey,
  encryptChunk,
  decryptChunk,
  encryptMetadata,
  decryptMetadata,
  generatePopKeyPair,
  exportPopPublicKeySpki,
  exportPopPrivateKeyPkcs8,
  importPopPublicKeySpki,
  importPopPrivateKeyPkcs8,
  signDownloadChallenge,
  verifyDownloadChallenge,
  wrapKeysWithPassword,
  unwrapKeysWithPassword,
  formatTransferFragmentRaw,
  formatTransferFragmentPwd,
  parseTransferFragment,
  generateEcdhKeyPair,
  exportEcdhPublicKeySpki,
  exportEcdhPrivateKeyPkcs8,
  importEcdhPublicKeySpki,
  importEcdhPrivateKeyPkcs8,
  computePublicKeyFingerprint,
  deriveEcdhSharedKey,
  wrapFileKeyWithEcdh,
  unwrapFileKeyWithEcdh,
  sha256Digest,
  StreamingSha256,
} from "@/lib/files/crypto";
import {
  AtomicMemoryFileRepository,
  setFileRepositoryForTests,
} from "@/lib/files/service";
import { POST as createTransferHandler } from "@/app/api/files/transfer/create/route";
import { POST as confirmTransferHandler } from "@/app/api/files/transfer/confirm/route";
import { POST as challengeHandler } from "@/app/api/files/download/challenge/route";
import { POST as consumeHandler } from "@/app/api/files/download/consume/route";
import { POST as createRequestHandler } from "@/app/api/files/request/create/route";
import { GET as getRequestPublicHandler } from "@/app/api/files/request/[token]/route";
import { POST as reserveItemHandler } from "@/app/api/files/request/[token]/reserve/route";
import { POST as confirmItemHandler } from "@/app/api/files/request/[token]/confirm/route";
import { GET as getManageHandler } from "@/app/api/files/manage/route";
import { POST as downloadItemHandler } from "@/app/api/files/manage/download/[itemId]/route";
import { DELETE as deleteItemHandler } from "@/app/api/files/manage/items/[itemId]/route";
import { POST as closeRequestHandler } from "@/app/api/files/manage/close/route";
import { POST as cleanupHandler, GET as cleanupGetHandler } from "@/app/api/files/cron/cleanup/route";
import { bytesToBase64Url } from "@/lib/secrets/crypto";

describe("ONCE — FILES Cryptography (Streaming AEAD, PoP, Key Wrapping & ECDH)", () => {
  it("derives distinct IVs for each chunk index, preventing GCM nonce reuse", () => {
    const baseIv = crypto.getRandomValues(new Uint8Array(8));
    const iv0 = deriveChunkIv(baseIv, 0);
    const iv1 = deriveChunkIv(baseIv, 1);
    const iv2 = deriveChunkIv(baseIv, 2);

    assert.equal(iv0.length, 12);
    assert.equal(iv1.length, 12);
    assert.equal(iv2.length, 12);

    const v0 = new DataView(iv0.buffer, iv0.byteOffset, 12).getUint32(8, false);
    const v1 = new DataView(iv1.buffer, iv1.byteOffset, 12).getUint32(8, false);
    const v2 = new DataView(iv2.buffer, iv2.byteOffset, 12).getUint32(8, false);

    assert.equal(v0, 0);
    assert.equal(v1, 1);
    assert.equal(v2, 2);
    assert.notDeepEqual(iv0, iv1);
  });

  it("verifies StreamingSha256 produces exact bit-for-bit results as crypto.subtle.digest", async () => {
    const chunks = [
      new TextEncoder().encode("Chunk 1: Lorem ipsum dolor sit amet, "),
      new TextEncoder().encode("Chunk 2: consectetur adipiscing elit. "),
      new TextEncoder().encode("Chunk 3: Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."),
    ];

    const streaming = new StreamingSha256();
    for (const c of chunks) {
      streaming.update(c);
    }
    const streamingDigest = streaming.digest();

    // Monolithic verification
    const full = new Uint8Array(chunks.reduce((acc, c) => acc + c.length, 0));
    let offset = 0;
    for (const c of chunks) {
      full.set(c, offset);
      offset += c.length;
    }
    const subtleDigest = await sha256Digest(full);

    assert.deepEqual(streamingDigest, subtleDigest);
    assert.equal(bytesToBase64Url(streamingDigest), bytesToBase64Url(subtleDigest));
  });

  it("encrypts and decrypts a chunk with AES-256-GCM and detects tampering", async () => {
    const fileKey = await generateFileKey();
    const baseIv = crypto.getRandomValues(new Uint8Array(8));
    const plaintext = new TextEncoder().encode("Hello, this is a secret chunk of file data!");

    const encrypted = await encryptChunk(
      plaintext.buffer,
      fileKey,
      baseIv,
      0,
      true,
      "test-token"
    );

    assert.equal(encrypted.byteLength, plaintext.byteLength + 16); // 16 bytes tag

    const decrypted = await decryptChunk(
      encrypted.buffer,
      fileKey,
      baseIv,
      0,
      true,
      "test-token"
    );

    assert.deepEqual(new Uint8Array(decrypted), plaintext);

    // Tampering test
    const tampered = new Uint8Array(encrypted);
    tampered[0] ^= 0x01; // flip one bit
    await assert.rejects(
      async () => {
        await decryptChunk(tampered.buffer, fileKey, baseIv, 0, true, "test-token");
      },
      /chunk_decryption_failed/
    );
  });

  it("fails decryption if chunk metadata AAD is altered or swapped", async () => {
    const fileKey = await generateFileKey();
    const baseIv = crypto.getRandomValues(new Uint8Array(8));
    const plaintext = new TextEncoder().encode("Sensitive payload");

    const encrypted = await encryptChunk(
      plaintext.buffer,
      fileKey,
      baseIv,
      0,
      false, // chunk 0, not last
      "token-A"
    );

    // Attempt decryption with wrong chunk index
    await assert.rejects(
      async () => {
        await decryptChunk(encrypted.buffer, fileKey, baseIv, 1, false, "token-A");
      },
      /chunk_decryption_failed/
    );

    // Attempt decryption with wrong token
    await assert.rejects(
      async () => {
        await decryptChunk(encrypted.buffer, fileKey, baseIv, 0, false, "token-B");
      },
      /chunk_decryption_failed/
    );
  });

  it("encrypts and decrypts file metadata, preserving zero-knowledge filename and mime type", async () => {
    const fileKey = await generateFileKey();
    const metadata = {
      originalName: "contratto_riservato_2026.pdf",
      originalSize: 10485760,
      mimeType: "application/pdf",
      chunkCount: 2,
      chunkSize: CHUNK_SIZE_BYTES,
      totalEncryptedSize: 10485760 + 32,
      sha256Hash: "mock-sha256-hash",
    };

    const { encryptedMetaB64, metaIvB64 } = await encryptMetadata(metadata, fileKey);
    assert.ok(encryptedMetaB64);
    assert.ok(metaIvB64);

    const decrypted = await decryptMetadata(encryptedMetaB64, metaIvB64, fileKey);
    assert.equal(decrypted.originalName, metadata.originalName);
    assert.equal(decrypted.mimeType, metadata.mimeType);
    assert.equal(decrypted.originalSize, metadata.originalSize);
    assert.equal(decrypted.sha256Hash, metadata.sha256Hash);
  });

  it("generates ECDSA PoP keypair, signs domain-separated challenge and verifies correctly", async () => {
    const popKeyPair = await generatePopKeyPair();
    const fileId = crypto.randomUUID();
    const challengeId = crypto.randomUUID();
    const challengeNonce = "0123456789abcdef0123456789abcdef";

    const signature = await signDownloadChallenge(
      popKeyPair.privateKey,
      fileId,
      challengeId,
      challengeNonce
    );

    assert.ok(signature);

    const isValid = await verifyDownloadChallenge(
      popKeyPair.publicKey,
      fileId,
      challengeId,
      challengeNonce,
      signature
    );

    assert.equal(isValid, true);

    // Replay on different challenge ID must fail
    const isReplayValid = await verifyDownloadChallenge(
      popKeyPair.publicKey,
      fileId,
      crypto.randomUUID(), // different challenge
      challengeNonce,
      signature
    );
    assert.equal(isReplayValid, false);
  });

  it("wraps and unwraps fileKey + popPrivateKey with user password using PBKDF2 (600k iterations)", async () => {
    const fileKey = await generateFileKey();
    const fileKeyBytes = await exportRawKey(fileKey);
    const popPair = await generatePopKeyPair();
    const popPrivateKeyPkcs8 = await exportPopPrivateKeyPkcs8(popPair.privateKey);

    const password = "SuperSecurePassword2026!#";

    const wrapped = await wrapKeysWithPassword(fileKeyBytes, popPrivateKeyPkcs8, password);
    assert.ok(wrapped.saltB64);
    assert.ok(wrapped.ivB64);
    assert.ok(wrapped.wrappedBundleB64);

    // Correct password unwrap
    const unwrapped = await unwrapKeysWithPassword(
      wrapped.saltB64,
      wrapped.ivB64,
      wrapped.wrappedBundleB64,
      password
    );

    assert.deepEqual(unwrapped.fileKeyBytes, fileKeyBytes);
    assert.equal(unwrapped.popPrivateKeyPkcs8, popPrivateKeyPkcs8);

    // Wrong password unwrap must fail
    await assert.rejects(
      async () => {
        await unwrapKeysWithPassword(
          wrapped.saltB64,
          wrapped.ivB64,
          wrapped.wrappedBundleB64,
          "WrongPassword123!"
        );
      },
      /wrong_password/
    );
  });

  it("computes SHA-256 fingerprint of ECDH public key for File Request guest authentication", async () => {
    const ecdhPair = await generateEcdhKeyPair();
    const pubSpki = await exportEcdhPublicKeySpki(ecdhPair.publicKey);
    const fingerprint = await computePublicKeyFingerprint(pubSpki);

    assert.ok(fingerprint);
    assert.equal(fingerprint.length, 43); // 32-byte sha256 in base64url is 43 chars

    // Stable fingerprint
    const fp2 = await computePublicKeyFingerprint(pubSpki);
    assert.equal(fingerprint, fp2);
  });

  it("performs ECDH P-256 key agreement between Creator and Guest and wraps ephemeral fileKey", async () => {
    // 1. Creator generates keypair
    const creatorPair = await generateEcdhKeyPair();
    const creatorPubSpki = await exportEcdhPublicKeySpki(creatorPair.publicKey);

    // 2. Guest generates ephemeral keypair
    const guestPair = await generateEcdhKeyPair();
    const guestPubSpki = await exportEcdhPublicKeySpki(guestPair.publicKey);

    // 3. Guest derives shared key using Creator's public key
    const importedCreatorPub = await importEcdhPublicKeySpki(creatorPubSpki);
    const guestSharedKey = await deriveEcdhSharedKey(guestPair.privateKey, importedCreatorPub);

    // 4. Guest generates fileKey and wraps it
    const fileKey = await generateFileKey();
    const fileKeyBytes = await exportRawKey(fileKey);
    const wrappedBundle = await wrapFileKeyWithEcdh(fileKeyBytes, guestSharedKey);

    // 5. Creator derives same shared key using Guest's public key
    const importedGuestPub = await importEcdhPublicKeySpki(guestPubSpki);
    const creatorSharedKey = await deriveEcdhSharedKey(creatorPair.privateKey, importedGuestPub);

    // 6. Creator unwraps fileKey
    const unwrappedFileKeyBytes = await unwrapFileKeyWithEcdh(
      wrappedBundle.wrappedKeyB64,
      wrappedBundle.ivB64,
      creatorPair.privateKey,
      importedGuestPub
    );

    assert.deepEqual(unwrappedFileKeyBytes, fileKeyBytes);
  });
});

describe("ONCE — File Transfer End-to-End API Workflows (Two-Phase Upload & PoP)", () => {
  let memoryRepo: AtomicMemoryFileRepository;

  beforeEach(() => {
    memoryRepo = new AtomicMemoryFileRepository();
    setFileRepositoryForTests(memoryRepo);
  });

  it("enforces Two-Phase Upload: download challenge is rejected until upload is confirmed", async () => {
    const popKeyPair = await generatePopKeyPair();
    const popPublicKeySpki = await exportPopPublicKeySpki(popKeyPair.publicKey);

    // 1. Create transfer slot (initially pending_upload)
    const createReq = new NextRequest("https://once.sh/api/files/transfer/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        popPublicKeySpki,
        encryptedMeta: { data: "meta_cipher", iv: "meta_iv" },
        sizeBytes: 1048576,
        maxDownloads: 2,
        expiration: "24h",
      }),
    });

    const createRes = await createTransferHandler(createReq);
    assert.equal(createRes.status, 201);
    const { transferToken } = await createRes.json();
    assert.ok(transferToken);

    // 2. Requesting challenge while still pending_upload MUST fail with 400
    const earlyChalReq = new NextRequest("https://once.sh/api/files/download/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transferToken }),
    });
    const earlyChalRes = await challengeHandler(earlyChalReq);
    assert.equal(earlyChalRes.status, 400);
    const earlyBody = await earlyChalRes.json();
    assert.equal(earlyBody.error, "file_not_ready");

    // 3. Confirm upload
    const confirmReq = new NextRequest("https://once.sh/api/files/transfer/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transferToken }),
    });
    const confirmRes = await confirmTransferHandler(confirmReq);
    assert.equal(confirmRes.status, 200);

    // 4. Request challenge now succeeds
    const chalReq = new NextRequest("https://once.sh/api/files/download/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transferToken }),
    });
    const chalRes = await challengeHandler(chalReq);
    assert.equal(chalRes.status, 200);
    const { challengeId, challengeNonce, fileId } = await chalRes.json();
    assert.ok(challengeId);

    // 5. Compute signature & consume download 1 of 2
    const signatureB64Url = await signDownloadChallenge(
      popKeyPair.privateKey,
      fileId,
      challengeId,
      challengeNonce
    );

    const consumeReq = new NextRequest("https://once.sh/api/files/download/consume", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        transferToken,
        challengeId,
        signatureB64Url,
      }),
    });

    const consumeRes = await consumeHandler(consumeReq);
    assert.equal(consumeRes.status, 200);
    const consumeBody = await consumeRes.json();
    assert.equal(consumeBody.success, true);
    assert.ok(consumeBody.downloadUrl);

    // 6. Replay attempt: re-using the consumed challenge must fail with 409!
    const replayReq = new NextRequest("https://once.sh/api/files/download/consume", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        transferToken,
        challengeId,
        signatureB64Url,
      }),
    });
    const replayRes = await consumeHandler(replayReq);
    assert.equal(replayRes.status, 409);

    // 7. Consume second download to reach max downloads
    const chal2Req = new NextRequest("https://once.sh/api/files/download/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transferToken }),
    });
    const chal2Res = await challengeHandler(chal2Req);
    assert.equal(chal2Res.status, 200);
    const chal2Data = await chal2Res.json();
    const sig2 = await signDownloadChallenge(
      popKeyPair.privateKey,
      fileId,
      chal2Data.challengeId,
      chal2Data.challengeNonce
    );
    const consume2Res = await consumeHandler(
      new NextRequest("https://once.sh/api/files/download/consume", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          transferToken,
          challengeId: chal2Data.challengeId,
          signatureB64Url: sig2,
        }),
      })
    );
    assert.equal(consume2Res.status, 200);

    // 8. Max downloads reached: requesting a new challenge must fail with 410!
    const nextChalReq = new NextRequest("https://once.sh/api/files/download/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transferToken }),
    });
    const nextChalRes = await challengeHandler(nextChalReq);
    assert.equal(nextChalRes.status, 410);
  });

  it("rejects transfer creation containing forbidden plaintext secrets or passwords", async () => {
    const popKeyPair = await generatePopKeyPair();
    const popPublicKeySpki = await exportPopPublicKeySpki(popKeyPair.publicKey);

    const badReq = new NextRequest("https://once.sh/api/files/transfer/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        popPublicKeySpki,
        encryptedMeta: { data: "test" },
        sizeBytes: 100,
        password: "secret_password_sent_to_server", // FORBIDDEN!
      }),
    });

    const res = await createTransferHandler(badReq);
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.error, "security_violation");
  });

  it("enforces maximum file size limit of 45 MB", async () => {
    const popKeyPair = await generatePopKeyPair();
    const popPublicKeySpki = await exportPopPublicKeySpki(popKeyPair.publicKey);

    const oversizeReq = new NextRequest("https://once.sh/api/files/transfer/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        popPublicKeySpki,
        encryptedMeta: { data: "test" },
        sizeBytes: 46 * 1024 * 1024, // 46 MB > 45 MB limit
      }),
    });

    const res = await createTransferHandler(oversizeReq);
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.error, "invalid_file_size");
  });

  it("CRITICAL CONCURRENCY: 15 concurrent consumers on a single-download file allow EXACTLY 1 download", async () => {
    const popKeyPair = await generatePopKeyPair();
    const popPublicKeySpki = await exportPopPublicKeySpki(popKeyPair.publicKey);

    // Create single download file
    const createRes = await createTransferHandler(
      new NextRequest("https://once.sh/api/files/transfer/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          popPublicKeySpki,
          encryptedMeta: { data: "test" },
          sizeBytes: 1024,
          maxDownloads: 1,
        }),
      })
    );
    const { transferToken } = await createRes.json();

    // Confirm transfer
    await confirmTransferHandler(
      new NextRequest("https://once.sh/api/files/transfer/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ transferToken }),
      })
    );

    // Prepare 15 distinct challenges
    const consumers = await Promise.all(
      Array.from({ length: 15 }, async (_, i) => {
        const chalRes = await challengeHandler(
          new NextRequest("https://once.sh/api/files/download/challenge", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-real-ip": `192.168.1.${i + 10}`,
            },
            body: JSON.stringify({ transferToken }),
          })
        );
        if (chalRes.status !== 200) return null;
        const { challengeId, challengeNonce, fileId } = await chalRes.json();
        const sig = await signDownloadChallenge(
          popKeyPair.privateKey,
          fileId,
          challengeId,
          challengeNonce
        );
        return { challengeId, sig };
      })
    );

    const validConsumers = consumers.filter((c): c is { challengeId: string; sig: string } => c !== null);

    // Execute concurrent consumption
    const results = await Promise.all(
      validConsumers.map((c) =>
        consumeHandler(
          new NextRequest("https://once.sh/api/files/download/consume", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              transferToken,
              challengeId: c.challengeId,
              signatureB64Url: c.sig,
            }),
          })
        )
      )
    );

    const successCount = results.filter((r) => r.status === 200).length;
    assert.equal(successCount, 1);
  });
});

describe("ONCE — File Request End-to-End API Workflows (Header Authentication)", () => {
  let memoryRepo: AtomicMemoryFileRepository;

  beforeEach(() => {
    memoryRepo = new AtomicMemoryFileRepository();
    setFileRepositoryForTests(memoryRepo);
  });

  it("creates request, accepts guest upload, lists items via X-Owner-Token, and closes request", async () => {
    // 1. Creator creates request
    const creatorPair = await generateEcdhKeyPair();
    const creatorPublicKeySpki = await exportEcdhPublicKeySpki(creatorPair.publicKey);

    const createReq = new NextRequest("https://once.sh/api/files/request/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: "Documenti KYC",
        creatorPublicKeySpki,
        maxFiles: 3,
        maxBytesPerFile: 10 * 1024 * 1024,
        expiration: "7d",
      }),
    });

    const createRes = await createRequestHandler(createReq);
    assert.equal(createRes.status, 201);
    const { requestToken, ownerToken } = await createRes.json();
    assert.ok(requestToken);
    assert.ok(ownerToken);

    // 2. Guest inspects request public info
    const getPubReq = new NextRequest(`https://once.sh/api/files/request/${requestToken}`);
    const getPubRes = await getRequestPublicHandler(getPubReq, {
      params: Promise.resolve({ token: requestToken }),
    });
    assert.equal(getPubRes.status, 200);
    const pubData = await getPubRes.json();
    assert.equal(pubData.title, "Documenti KYC");
    assert.equal(pubData.status, "active");

    // 3. Guest reserves upload slot
    const reserveReq = new NextRequest(`https://once.sh/api/files/request/${requestToken}/reserve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sizeBytes: 500000 }),
    });
    const reserveRes = await reserveItemHandler(reserveReq, {
      params: Promise.resolve({ token: requestToken }),
    });
    assert.equal(reserveRes.status, 201);
    const { slotId } = await reserveRes.json();
    assert.ok(slotId);

    // 4. Guest confirms upload
    const guestPair = await generateEcdhKeyPair();
    const guestPubSpki = await exportEcdhPublicKeySpki(guestPair.publicKey);

    const confirmReq = new NextRequest(`https://once.sh/api/files/request/${requestToken}/confirm`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        slotId,
        guestPublicKeySpki: guestPubSpki,
        wrappedKeyBundle: { iv: "iv_b64", key: "key_b64", baseIv: "base_iv" },
        encryptedMeta: { data: "enc_meta", iv: "meta_iv" },
      }),
    });
    const confirmRes = await confirmItemHandler(confirmReq, {
      params: Promise.resolve({ token: requestToken }),
    });
    assert.equal(confirmRes.status, 200);

    // 5. Accessing manage without header must return 401
    const unauthManageReq = new NextRequest("https://once.sh/api/files/manage");
    const unauthManageRes = await getManageHandler(unauthManageReq);
    assert.equal(unauthManageRes.status, 401);

    // 6. Creator views manager dashboard with X-Owner-Token header
    const manageReq = new NextRequest("https://once.sh/api/files/manage", {
      headers: { "X-Owner-Token": ownerToken },
    });
    const manageRes = await getManageHandler(manageReq);
    assert.equal(manageRes.status, 200);
    const manageData = await manageRes.json();
    assert.equal(manageData.items.length, 1);
    assert.equal(manageData.items[0].id, slotId);

    // 7. Creator requests signed download link
    const dlReq = new NextRequest(`https://once.sh/api/files/manage/download/${slotId}`, {
      method: "POST",
      headers: { "X-Owner-Token": ownerToken },
    });
    const dlRes = await downloadItemHandler(dlReq, {
      params: Promise.resolve({ itemId: slotId }),
    });
    assert.equal(dlRes.status, 200);
    const dlData = await dlRes.json();
    assert.ok(dlData.downloadUrl);

    // 8. Creator deletes single item
    const delReq = new NextRequest(`https://once.sh/api/files/manage/items/${slotId}`, {
      method: "DELETE",
      headers: { "X-Owner-Token": ownerToken },
    });
    const delRes = await deleteItemHandler(delReq, {
      params: Promise.resolve({ itemId: slotId }),
    });
    assert.equal(delRes.status, 200);

    // 9. Creator closes request
    const closeReq = new NextRequest("https://once.sh/api/files/manage/close", {
      method: "POST",
      headers: { "X-Owner-Token": ownerToken },
    });
    const closeRes = await closeRequestHandler(closeReq);
    assert.equal(closeRes.status, 200);

    // Request is now closed
    const afterClose = await getManageHandler(manageReq);
    const afterCloseData = await afterClose.json();
    assert.equal(afterCloseData.request.status, "closed");
  });
});

describe("ONCE — FILES CRON & Storage Deletion Hardening", () => {
  let memoryRepo: AtomicMemoryFileRepository;
  const originalEnv = process.env.CRON_SECRET;

  beforeEach(() => {
    memoryRepo = new AtomicMemoryFileRepository();
    setFileRepositoryForTests(memoryRepo);
    delete process.env.CRON_SECRET;
  });

  it("CRON fails closed with 503 if CRON_SECRET is not configured", async () => {
    delete process.env.CRON_SECRET;

    const req = new NextRequest("https://once.sh/api/files/cron/cleanup", {
      method: "POST",
      headers: { Authorization: "Bearer some-token" },
    });

    const res = await cleanupHandler(req);
    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.error, "service_unavailable");
  });

  it("CRON rejects requests with missing or invalid Bearer token with 401", async () => {
    process.env.CRON_SECRET = "super-secret-cron-key-12345";

    // Missing header
    const noHeaderReq = new NextRequest("https://once.sh/api/files/cron/cleanup", {
      method: "POST",
    });
    const noHeaderRes = await cleanupHandler(noHeaderReq);
    assert.equal(noHeaderRes.status, 401);

    // Wrong token
    const wrongHeaderReq = new NextRequest("https://once.sh/api/files/cron/cleanup", {
      method: "POST",
      headers: { Authorization: "Bearer wrong-token" },
    });
    const wrongHeaderRes = await cleanupHandler(wrongHeaderReq);
    assert.equal(wrongHeaderRes.status, 401);
  });

  it("CRON supports GET requests from Vercel Cron when authenticated", async () => {
    process.env.CRON_SECRET = "vercel-cron-secret-key-999";

    const getReq = new NextRequest("https://once.sh/api/files/cron/cleanup", {
      method: "GET",
      headers: { Authorization: "Bearer vercel-cron-secret-key-999" },
    });

    const res = await cleanupGetHandler(getReq);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
  });

  it("CRON claims deletion lease batch, executes deletion, and cleans up expired files", async () => {
    process.env.CRON_SECRET = "valid-secret-key-xyz";

    // Enqueue an item directly for deletion
    memoryRepo.deletionQueue.set("transfers/test-item.enc", {
      id: "queue-item-1",
      storagePath: "transfers/test-item.enc",
      deleteAfter: new Date(Date.now() - 1000).toISOString(), // expired
      attempts: 0,
      lastError: null,
      claimExpiresAt: null,
    });

    const req = new NextRequest("https://once.sh/api/files/cron/cleanup", {
      method: "POST",
      headers: { Authorization: "Bearer valid-secret-key-xyz" },
    });

    const res = await cleanupHandler(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.storageDeletion.claimed, 1);
    assert.equal(body.storageDeletion.deleted, 1);

    // Queue item should now be removed from deletion queue
    assert.equal(memoryRepo.deletionQueue.size, 0);

    // Restore original env
    if (originalEnv) process.env.CRON_SECRET = originalEnv;
  });

  it("reclaims orphan file_request_items in pending_upload status older than 2 hours", async () => {
    const twoHoursAndHalfAgo = new Date(Date.now() - 2.5 * 60 * 60 * 1000).toISOString();
    memoryRepo.requestItems.set("orphan-item", {
      id: "orphan-item",
      requestId: "req-1",
      storagePath: "requests/req-1/orphan-item.enc",
      sizeBytes: 500000,
      guestPublicKeySpki: "",
      wrappedKeyBundle: "{}",
      encryptedMeta: "{}",
      status: "pending_upload",
      createdAt: twoHoursAndHalfAgo,
    });

    const stats = await memoryRepo.cleanupExpiredFiles();
    assert.equal(stats.expiredPendingItems, 1);
    const item = memoryRepo.requestItems.get("orphan-item");
    assert.equal(item?.status, "expired");
    assert.ok(memoryRepo.deletionQueue.has("requests/req-1/orphan-item.enc"));
  });
});
