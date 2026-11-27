-- Add composite indexes to MediaItem for faster paginated queries.
-- Covers the three optional filter columns (mediaType, folderCategory, dateAddedMs)
-- combined with the ORDER BY column (receivedAt) so the planner can satisfy
-- both WHERE and ORDER BY from one index scan without a separate sort step.

CREATE INDEX "MediaItem_deviceId_mediaType_receivedAt_idx"
  ON "MediaItem"("deviceId", "mediaType", "receivedAt" DESC);

CREATE INDEX "MediaItem_deviceId_folderCategory_receivedAt_idx"
  ON "MediaItem"("deviceId", "folderCategory", "receivedAt" DESC);

CREATE INDEX "MediaItem_deviceId_dateAddedMs_idx"
  ON "MediaItem"("deviceId", "dateAddedMs" DESC);
