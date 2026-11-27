-- CreateTable
CREATE TABLE "Device" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "enrollmentToken" TEXT NOT NULL,
    "label" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" DATETIME
);

-- CreateTable
CREATE TABLE "Event" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "clientEventId" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "packageName" TEXT NOT NULL,
    "appLabel" TEXT NOT NULL,
    "conversationTitle" TEXT,
    "sender" TEXT,
    "text" TEXT NOT NULL,
    "isGroup" BOOLEAN NOT NULL,
    "postedAt" BIGINT NOT NULL,
    "capturedAt" BIGINT NOT NULL,
    "receivedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY ("deviceId") REFERENCES "Device" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "Device_enrollmentToken_key" ON "Device"("enrollmentToken" ASC);

-- CreateIndex
CREATE INDEX "Event_deviceId_receivedAt_idx" ON "Event"("deviceId" ASC, "receivedAt" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Event_clientEventId_key" ON "Event"("clientEventId" ASC);

