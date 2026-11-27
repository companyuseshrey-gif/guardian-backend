import assert from "node:assert/strict";
import { test } from "node:test";
import { StorageItemSchema, StorageNegotiateSchema } from "./storageSync.js";
const validItem = {
    clientItemId: "9f2c6e10-1b3a-4c8e-8d2a-000000000001",
    mediaType: "image",
    uri: "content://com.android.externalstorage.documents/tree/primary%3ADCIM/document/primary%3ADCIM%2FIMG_0001.jpg",
    displayName: "IMG_0001.jpg",
    mimeType: "image/jpeg",
    sizeBytes: 2_345_678,
    dateAddedMs: 1_734_500_000_000,
    dateModifiedMs: 1_734_500_000_000,
    width: 4032,
    height: 3024,
    durationMs: null,
    thumbnailBase64: null,
    contentHash: "a".repeat(64),
    capturedAt: 1_734_500_000_123,
};
test("StorageItemSchema accepts a fully-populated image item", () => {
    const result = StorageItemSchema.safeParse(validItem);
    assert.equal(result.success, true);
});
test("StorageItemSchema accepts a document with most optional fields omitted", () => {
    const result = StorageItemSchema.safeParse({
        clientItemId: "doc-item-1",
        mediaType: "document",
        uri: "content://com.android.externalstorage.documents/document/primary%3ADownload%2Freport.pdf",
        capturedAt: 1_734_500_000_123,
    });
    assert.equal(result.success, true);
});
test("StorageItemSchema rejects a clientItemId that could path-traverse", () => {
    const result = StorageItemSchema.safeParse({ ...validItem, clientItemId: "../../etc/passwd" });
    assert.equal(result.success, false);
});
test("StorageItemSchema rejects a clientItemId containing a path separator", () => {
    const result = StorageItemSchema.safeParse({ ...validItem, clientItemId: "sub/dir" });
    assert.equal(result.success, false);
});
test("StorageItemSchema rejects a malformed contentHash", () => {
    const result = StorageItemSchema.safeParse({ ...validItem, contentHash: "not-a-hash" });
    assert.equal(result.success, false);
});
test("StorageItemSchema accepts audio as a mediaType", () => {
    const result = StorageItemSchema.safeParse({ ...validItem, mediaType: "audio", mimeType: "audio/mpeg" });
    assert.equal(result.success, true);
});
test("StorageItemSchema rejects an unknown mediaType", () => {
    const result = StorageItemSchema.safeParse({ ...validItem, mediaType: "spreadsheet" });
    assert.equal(result.success, false);
});
test("StorageItemSchema rejects a negative sizeBytes", () => {
    const result = StorageItemSchema.safeParse({ ...validItem, sizeBytes: -5 });
    assert.equal(result.success, false);
});
test("StorageNegotiateSchema caps the batch at 200 items", () => {
    const items = Array.from({ length: 201 }, (_, i) => ({
        ...validItem,
        clientItemId: `9f2c6e10-1b3a-4c8e-8d2a-${String(i).padStart(12, "0")}`,
    }));
    const result = StorageNegotiateSchema.safeParse({ deviceId: "dev_test", items });
    assert.equal(result.success, false);
});
test("StorageNegotiateSchema accepts an empty items array (nothing new to negotiate)", () => {
    const result = StorageNegotiateSchema.safeParse({ deviceId: "dev_test", items: [] });
    assert.equal(result.success, true);
});
