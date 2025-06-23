-- CreateTable
CREATE TABLE "AssistantID" (
    "id" SERIAL NOT NULL,
    "value" TEXT NOT NULL,
    "userId" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AssistantID_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AssistantID_userId_idx" ON "AssistantID"("userId");

-- AddForeignKey
ALTER TABLE "AssistantID" ADD CONSTRAINT "AssistantID_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
