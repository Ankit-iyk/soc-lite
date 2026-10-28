-- Additive migration for durable event analysis jobs.
CREATE TABLE "processing_jobs" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "availableAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "failedAt" TIMESTAMP(3),
    "lastError" TEXT,
    "processingMs" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "processing_jobs_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "processing_jobs_eventId_key"
ON "processing_jobs"("eventId");

CREATE INDEX "processing_jobs_status_availableAt_idx"
ON "processing_jobs"("status", "availableAt");

ALTER TABLE "processing_jobs"
ADD CONSTRAINT "processing_jobs_eventId_fkey"
FOREIGN KEY ("eventId") REFERENCES "events"("id")
ON DELETE CASCADE ON UPDATE CASCADE;
