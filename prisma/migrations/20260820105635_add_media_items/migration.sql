-- CreateTable
CREATE TABLE "MediaItem" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "clientItemId" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "mediaType" TEXT NOT NULL,
    "uri" TEXT NOT NULL,
    "displayName" TEXT,
    "mimeType" TEXT,
    "sizeBytes" BIGINT,
    "dateAddedMs" BIGINT,
    "dateModifiedMs" BIGINT,
    "width" INTEGER,
    "height" INTEGER,
    "durationMs" BIGINT,
    "thumbnailBase64" TEXT,
    "capturedAt" BIGINT NOT NULL,
    "receivedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "MediaItem_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "MediaItem_clientItemId_key" ON "MediaItem"("clientItemId");

-- CreateIndex
CREATE INDEX "MediaItem_deviceId_receivedAt_idx" ON "MediaItem"("deviceId", "receivedAt");

