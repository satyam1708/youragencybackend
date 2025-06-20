/*
  Warnings:

  - You are about to drop the column `createdAt` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `updatedAt` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "createdAt",
DROP COLUMN "updatedAt",
ADD COLUMN     "consentGivenAt" TIMESTAMP(3),
ADD COLUMN     "isEmailVerified" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "verificationToken" TEXT,
ADD COLUMN     "verificationTokenExpiry" TIMESTAMP(3),
ALTER COLUMN "type" DROP DEFAULT;
